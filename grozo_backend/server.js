const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const https = require('https');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'your_mongodb_connection_string_here'; // Replace with your MongoDB Atlas URI

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// CORS middleware: allow known frontends for development
const ALLOWED_FRONTENDS = [
  'https://grozo.online',
  'https://grozo-admin.netlify.app',
  'https://grozo-dashboard.netlify.app',
  'https://grozo-deliverypartner.netlify.app'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const cleanOrigin = origin ? origin.replace(/\/$/, '') : '';
  
  // Allow requests if:
  // 1. No origin (same-origin requests from backend itself), OR
  // 2. Origin is in the whitelist, OR
  // 3. Origin is localhost/127.0.0.1 (for local development)
  const isLocalhost = cleanOrigin.startsWith('http://localhost') || cleanOrigin.startsWith('http://127.0.0.1');
  const isAllowed = !origin || ALLOWED_FRONTENDS.includes(cleanOrigin) || isLocalhost;
  
  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Define Mongoose schemas
const productSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  price: Number,
  // Add other fields as needed
});

const orderSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  date: String,
  items: Array,
  userName: String,
  userPhone: String,
  location: Object,
  subtotal: Number,
  fees: Object,
  discount: Number,
  total: Number,
  status: String,
  history: Array,
});

const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  passwordHash: String,
  role: String,
  name: String,
  meta: Object,
});

const tokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  userId: String,
  createdAt: String,
});

const feeSchema = new mongoose.Schema({
  _id: String, // Use _id for key
  value: Object,
});

const promoSchema = new mongoose.Schema({
  id: String,
  // Add fields
});

const productOverrideSchema = new mongoose.Schema({
  id: String,
  // Add fields
});

// Models
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);
const Fee = mongoose.model('Fee', feeSchema);
const Promo = mongoose.model('Promo', promoSchema);
const ProductOverride = mongoose.model('ProductOverride', productOverrideSchema);

// Initialize default admin
async function initDB() {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
      const admin = new User({
        id: 'u_admin',
        username: 'admin',
        passwordHash: sha256('admin123'),
        role: 'admin',
        name: 'Administrator'
      });
      await admin.save();
      console.log('Created default admin user: username=admin password=admin123 (change immediately)');
    }
  } catch (err) {
    console.error('Error initializing DB:', err);
  }
}

initDB();

// --- auth middleware ---
async function authMiddleware(requiredRoles = []) {
  return async (req, res, next) => {
    const auth = req.headers.authorization || '';
    const match = auth.match(/^Bearer\s+(\S+)$/i);
    if (!match) return res.status(401).json({ error: 'Missing token' });
    const token = match[1];
    try {
      const t = await Token.findOne({ token });
      if (!t) return res.status(401).json({ error: 'Invalid token' });
      const user = await User.findOne({ id: t.userId });
      if (!user) return res.status(401).json({ error: 'User not found' });
      if (requiredRoles.length && !requiredRoles.includes(user.role)) return res.status(403).json({ error: 'Forbidden' });
      req.user = user;
      next();
    } catch (err) {
      res.status(500).json({ error: 'Server error' });
    }
  };
}

// --- Auth routes ---
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.passwordHash !== sha256(password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = generateToken();
    const newToken = new Token({ token, userId: user.id, createdAt: new Date().toISOString() });
    await newToken.save();
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delivery registration (creates delivery user if not exists)
app.post('/api/auth/register-delivery', async (req, res) => {
  const { phone, name, vehicle, vehicleNo } = req.body || {};
  if (!phone || !name) return res.status(400).json({ error: 'phone and name required' });
  try {
    let user = await User.findOne({ username: phone, role: 'delivery' });
    if (!user) {
      user = new User({
        id: 'u_' + Date.now(),
        username: phone,
        passwordHash: sha256(phone.slice(-4) || '0000'),
        role: 'delivery',
        name,
        meta: { vehicle, vehicleNo }
      });
      await user.save();
    }
    const token = generateToken();
    const newToken = new Token({ token, userId: user.id, createdAt: new Date().toISOString() });
    await newToken.save();
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Products ---
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({});
    res.json({ products });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const p = await Product.findOne({ id: req.params.id });
    if (!p) return res.status(404).json({ error: 'Product not found' });
    res.json(p);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/products', authMiddleware(['admin']), async (req, res) => {
  const data = req.body || {};
  if (!data.id || !data.name) return res.status(400).json({ error: 'id and name required' });
  try {
    const existing = await Product.findOne({ id: data.id });
    if (existing) return res.status(400).json({ error: 'Product id already exists' });
    const product = new Product(data);
    await product.save();
    res.json({ ok: true, product });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/products/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    const product = await Product.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!product) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true, product });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/products/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    await Product.deleteOne({ id: req.params.id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Orders ---
app.post('/api/orders', async (req, res) => {
  const data = req.body || {};
  if (!data.items || !Array.isArray(data.items) || data.items.length === 0) return res.status(400).json({ error: 'items required' });
  try {
    const id = 'ORD' + Date.now().toString().slice(-8);
    const order = new Order({
      id,
      date: new Date().toLocaleString(),
      items: data.items,
      userName: data.userName || '',
      userPhone: data.userPhone || '',
      location: data.location || null,
      subtotal: data.subtotal || 0,
      fees: data.fees || {},
      discount: data.discount || 0,
      total: data.total || 0,
      status: 'pending',
      history: [{ status: 'pending', at: new Date().toISOString() }]
    });
    await order.save();
    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders', authMiddleware(['admin','delivery']), async (req, res) => {
  try {
    const orders = await Order.find({});
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/:id', authMiddleware(['admin','delivery']), async (req, res) => {
  try {
    const order = await Order.findOne({ id: req.params.id });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/orders/:id/status', authMiddleware(['admin','delivery']), async (req, res) => {
  const { status } = req.body || {};
  if (!status) return res.status(400).json({ error: 'status required' });
  try {
    const order = await Order.findOne({ id: req.params.id });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    order.status = status;
    order.history = order.history || [];
    order.history.push({ status, by: req.user.username, at: new Date().toISOString() });
    await order.save();
    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders/:id/assign-delivery', authMiddleware(['admin']), async (req, res) => {
  const { deliveryUserId } = req.body || {};
  if (!deliveryUserId) return res.status(400).json({ error: 'deliveryUserId required' });
  try {
    const order = await Order.findOne({ id: req.params.id });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    const deliveryUser = await User.findOne({ id: deliveryUserId, role: 'delivery' });
    if (!deliveryUser) return res.status(404).json({ error: 'Delivery user not found' });
    order.assignedTo = { id: deliveryUser.id, username: deliveryUser.username, name: deliveryUser.name };
    order.status = 'dispatched';
    order.history = order.history || [];
    order.history.push({ status: 'dispatched', by: req.user.username, at: new Date().toISOString() });
    await order.save();
    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Find order by dispatch code (public)
app.get('/api/orders/dispatch/:code', async (req, res) => {
  const code = (req.params.code || '').toString();
  if (!code) return res.status(400).json({ error: 'code required' });
  try {
    const order = await Order.findOne({ 'dispatch.code': code });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json({ order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Generic order update (admin/delivery) - merges provided fields into order
app.put('/api/orders/:id', authMiddleware(['admin','delivery']), async (req, res) => {
  try {
    const toMerge = req.body || {};
    delete toMerge.id;
    const order = await Order.findOneAndUpdate({ id: req.params.id }, { $set: toMerge }, { new: true });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    order.history = order.history || [];
    order.history.push({ updatedBy: req.user.username, at: new Date().toISOString(), changes: Object.keys(toMerge) });
    await order.save();
    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// promos
app.get('/api/promos', async (req, res) => {
  try {
    const promos = await Promo.find({});
    res.json({ promos });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/promos', authMiddleware(['admin']), async (req, res) => {
  try {
    await Promo.deleteMany({});
    const promos = Array.isArray(req.body) ? req.body : (req.body.promos || []);
    await Promo.insertMany(promos);
    res.json({ ok: true, promos });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Users list (admin) and deliveries (public list) ---
app.get('/api/delivery-partners', authMiddleware(['admin']), async (req, res) => {
  try {
    const deliveries = await User.find({ role: 'delivery' });
    res.json({ deliveries });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', authMiddleware(['admin','delivery']), (req, res) => {
  res.json({ user: req.user });
});

// --- simple admin endpoints for fees/promos ---
app.get('/api/fees', async (req, res) => {
  try {
    const feeDoc = await Fee.findOne({ _id: 'fees' });
    res.json({ fees: feeDoc ? feeDoc.value : {} });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/fees', authMiddleware(['admin']), async (req, res) => {
  try {
    const fees = req.body || {};
    await Fee.findOneAndUpdate({ _id: 'fees' }, { value: fees }, { upsert: true });
    res.json({ ok: true, fees });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Product Overrides (price/image/outOfStock) ---
app.get('/api/product-overrides', async (req, res) => {
  try {
    const overrides = await ProductOverride.find({});
    const overridesObj = {};
    overrides.forEach(o => overridesObj[o.id] = o);
    res.json({ overrides: overridesObj });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/product-overrides', authMiddleware(['admin']), async (req, res) => {
  try {
    const overrides = req.body || {};
    await ProductOverride.deleteMany({});
    const docs = Object.keys(overrides).map(id => ({ id, ...overrides[id] }));
    await ProductOverride.insertMany(docs);
    res.json({ ok: true, overrides });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/product-overrides/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    const id = req.params.id;
    const update = req.body || {};
    const override = await ProductOverride.findOneAndUpdate({ id }, update, { upsert: true, new: true });
    res.json({ ok: true, override });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Last update timestamp for polling
app.get('/api/last-update', (req, res) => {
  res.json({ lastUpdate: Date.now() });
});

// fallback
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Frontend helper endpoints ---
const FRONTEND_LINKS = {
  home: 'https://grozo.online/',
  admin: 'https://grozo-admin.netlify.app/',
  dashboard: 'https://grozo-dashboard.netlify.app/',
  delivery: 'https://grozo-deliverypartner.netlify.app/'
};

app.get('/api/frontend-links', (req, res) => res.json(FRONTEND_LINKS));

// --- Google sign-in verification endpoint ---
const GOOGLE_CLIENT_ID = '1054365989272-e3t05dqp8k4vf3slii9ofdiujsdq7js0.apps.googleusercontent.com';

function verifyGoogleIdToken(idToken) {
  const url = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken);
  return new Promise((resolve, reject) => {
    https.get(url, (resp) => {
      let data = '';
      resp.on('data', (chunk) => { data += chunk; });
      resp.on('end', () => {
        try {
          const json = JSON.parse(data || '{}');
          if (json.error_description || json.error) return reject(new Error(json.error_description || json.error));
          resolve(json);
        } catch (e) { reject(e); }
      });
    }).on('error', (err) => reject(err));
  });
}

app.post('/api/auth/google', async (req, res) => {
  const { id_token } = req.body || {};
  if (!id_token) return res.status(400).json({ error: 'id_token required' });
  try {
    const info = await verifyGoogleIdToken(id_token);
    // validate audience
    if (!info || info.aud !== GOOGLE_CLIENT_ID) return res.status(401).json({ error: 'Invalid id_token (aud mismatch)' });

    const email = info.email;
    const name = info.name || '';
    const picture = info.picture || '';
    const sub = info.sub || '';

    let user = await User.findOne({ username: email, role: 'customer' });
    if (!user) {
      user = new User({
        id: 'u_' + Date.now(),
        username: email,
        role: 'customer',
        name,
        picture,
        meta: { googleSub: sub }
      });
      await user.save();
    } else {
      // update fields
      user.name = name || user.name;
      user.picture = picture || user.picture;
      user.meta = Object.assign({}, user.meta || {}, { googleSub: sub });
      await user.save();
    }

    const token = generateToken();
    const newToken = new Token({ token, userId: user.id, createdAt: new Date().toISOString() });
    await newToken.save();

    res.json({ token, user: { id: user.id, name: user.name, email: user.username, picture: user.picture } });
  } catch (err) {
    console.error('Google token verification error:', err && err.message ? err.message : err);
    res.status(500).json({ error: 'verification_failed', details: (err && err.message) || String(err) });
  }
});

app.get('/go/home', (req, res) => res.redirect(FRONTEND_LINKS.home));
app.get('/go/admin', (req, res) => res.redirect(FRONTEND_LINKS.admin));
app.get('/go/dashboard', (req, res) => res.redirect(FRONTEND_LINKS.dashboard));
app.get('/go/delivery', (req, res) => res.redirect(FRONTEND_LINKS.delivery));

app.listen(PORT, () => console.log(`Backend listening on http://localhost:${PORT}`));
