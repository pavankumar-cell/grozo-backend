const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const https = require('https');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://bpavan422_db_user:s5mIhGPgtgF7F9TH@grozo-cluster.asew17j.mongodb.net/?appName=grozo-cluster'; // Replace with your MongoDB Atlas URI

const app = express();
app.use(express.json());

const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || process.env.cloud_name;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY || process.env.api_key;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || process.env.api_secret;

cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype || !file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files are allowed'));
    }
    cb(null, true);
  },
});

// Global last update timestamp
let globalLastUpdate = Date.now();

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    initDB();
  })
  .catch(err => console.error('MongoDB connection error:', err));

// CORS middleware: allow known frontends for development
const ALLOWED_FRONTENDS = (process.env.ALLOWED_FRONTENDS || 'https://grozo.online,https://grozo-admin.netlify.app,https://grozo-dashboard.netlify.app,https://grozo-deliverypartner.netlify.app').split(',');

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
  image: String,
  category: String,
  qtyLimit: Number,
  outOfStock: Boolean,
}, { strict: false }); // allow extra fields from future updates

const orderSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  date: String,
  items: Array,
  userName: String,
  userPhone: String,
  userEmail: String,
  receiverPhone: String,
  deliveryTimeSlot: String,
  location: Object,
  subtotal: Number,
  fees: Object,
  discount: Number,
  total: Number,
  paymentMethod: String,
  orderMode: String,   // 'b2b' | 'b2c'
  orderType: String,   // 'b2b' | 'b2c'
  channel: String,     // 'b2b' | 'b2c'
  businessType: String,
  status: String,
  history: Array,
  assignedTo: Object,
  deliveryPartnerLocation: Object, // { latitude, longitude, lastUpdated, name }
  dispatch: Object, // { code, sentAt }
  deliveryCode: String, // 4-digit code for delivery verification
  // Delivery partner information
  pickedUpByName: String,
  pickedUpByPhone: String,
  pickedUpAt: String,
  deliveredByName: String,
  deliveredByPhone: String,
  deliveredAt: String,
  deliveryPartnerVehicle: String,
  deliveryPartnerVehicleNo: String,
  darkStoreId: String,
  darkStoreName: String,
  darkStore: Object,
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
  storeKey: String,
  storeName: String,
  value: Object,
});

const b2bFeeSchema = new mongoose.Schema({
  _id: String, // Use _id for key
  storeKey: String,
  storeName: String,
  value: Object,
});

const promoSchema = new mongoose.Schema({
  id: String,
  storeKey: String,
  storeName: String,
  // allow arbitrary promo fields (discount, type, meta etc.)
}, { strict: false });

const b2bPromoSchema = new mongoose.Schema({
  id: String,
  storeKey: String,
  storeName: String,
  // allow arbitrary promo fields (discount, type, meta etc.)
}, { strict: false });

const productOverrideSchema = new mongoose.Schema({
  id: String,
  storeKey: String,
  storeName: String,
  // allow arbitrary override fields (price, outOfStock, limit, image, etc.)
}, { strict: false });

const b2bProductOverrideSchema = new mongoose.Schema({
  id: String,
  storeKey: String,
  storeName: String,
  // allow arbitrary override fields (price, outOfStock, limit, image, etc.)
}, { strict: false });

const b2bProductSchema = new mongoose.Schema({
  id: String,
  storeKey: String,
  storeName: String,
  // allow arbitrary product fields (name, category, image, prices, qtyLimit etc.)
}, { strict: false });

const darkStoreLocationSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  address: String,
  latitude: Number,
  longitude: Number,
  createdAt: String,
}, { strict: false });

// Models
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);
const Fee = mongoose.model('Fee', feeSchema);
const B2BFee = mongoose.model('B2BFee', b2bFeeSchema);
const Promo = mongoose.model('Promo', promoSchema);
const B2BPromo = mongoose.model('B2BPromo', b2bPromoSchema);
const ProductOverride = mongoose.model('ProductOverride', productOverrideSchema);
const B2BProductOverride = mongoose.model('B2BProductOverride', b2bProductOverrideSchema);
const B2BProduct = mongoose.model('B2BProduct', b2bProductSchema);
const DarkStoreLocation = mongoose.model('DarkStoreLocation', darkStoreLocationSchema);

const DEFAULT_STORE_KEY = 'default_location';
const DEFAULT_STORE_NAME = 'Default Location';

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

const BENEFICIARY_CODE_LIMITS = {
  GBC14PA4N260: 10,
  GBC6P1VL4R32: 25,
  GBC3L021K96P: 50,
};

function normalizeStoreName(value) {
  return (value || '').toString().trim().replace(/\s+/g, ' ');
}

function toStoreKey(storeName) {
  return normalizeStoreName(storeName).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

function getStoreMetaFromRequest(req) {
  const queryStore = req && req.query ? req.query.store : '';
  const queryStoreKey = req && req.query ? (req.query.storeKey || '') : '';
  const bodyStore = req && req.body && !Array.isArray(req.body) ? req.body.store : '';
  const bodyStoreKey = req && req.body && !Array.isArray(req.body) ? (req.body.storeKey || '') : '';
  const storeName = normalizeStoreName(queryStore || bodyStore || '');
  const storeKey = toStoreKey(storeName || bodyStoreKey || queryStoreKey);
  return { storeName, storeKey };
}

function getGlobalStoreQuery() {
  return { $or: [{ storeKey: { $exists: false } }, { storeKey: null }, { storeKey: '' }] };
}

function getStoreQuery(storeKey) {
  if (!storeKey) return getGlobalStoreQuery();
  return { storeKey };
}

function sanitizeOverrideDoc(doc) {
  const data = doc && typeof doc.toObject === 'function' ? doc.toObject() : (doc || {});
  const { _id, __v, id, storeKey, storeName, ...rest } = data;
  return rest;
}

function sanitizeIncomingOverrideValue(value) {
  const src = (value && typeof value === 'object') ? value : {};
  const { _id, __v, id, storeKey, storeName, ...rest } = src;
  return rest;
}

function normalizeStockNumber(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  if (n < 0) return 0;
  return Math.floor(n);
}

function applyStockRulesToOverrideDoc(overrideDoc) {
  const stock = normalizeStockNumber(overrideDoc.availableStock);
  if (stock === null) return false;

  overrideDoc.availableStock = stock;

  const qtyLimit = Number(overrideDoc.qtyLimit);
  if (!Number.isFinite(qtyLimit) || qtyLimit > stock) {
    overrideDoc.qtyLimit = stock;
  }

  if (stock <= 0) {
    overrideDoc.outOfStock = true;
    overrideDoc.qtyLimit = 0;
  }
  return true;
}

async function decrementOrderItemsStock({ items, isB2B, storeKey, storeName }) {
  const OverrideModel = isB2B ? B2BProductOverride : ProductOverride;
  const updated = [];

  for (const rawItem of (Array.isArray(items) ? items : [])) {
    const productId = rawItem && rawItem.id ? String(rawItem.id) : '';
    const qty = normalizeStockNumber(rawItem && rawItem.qty);
    if (!productId || qty === null || qty <= 0) continue;

    const overrideDoc = await OverrideModel.findOne({ id: productId, storeKey });
    if (!overrideDoc) continue;

    const currentStock = normalizeStockNumber(overrideDoc.availableStock);
    if (currentStock === null) continue;

    overrideDoc.availableStock = Math.max(0, currentStock - qty);
    applyStockRulesToOverrideDoc(overrideDoc);
    if (storeName) overrideDoc.storeName = storeName;
    await overrideDoc.save();

    updated.push({
      id: productId,
      availableStock: overrideDoc.availableStock,
      qtyLimit: overrideDoc.qtyLimit,
      outOfStock: overrideDoc.outOfStock === true
    });
  }

  return updated;
}

function getEffectiveProductOverrideStoreMeta(req) {
  const { storeKey, storeName } = getStoreMetaFromRequest(req);
  if (storeKey) {
    return { storeKey, storeName: storeName || storeKey };
  }
  return { storeKey: DEFAULT_STORE_KEY, storeName: DEFAULT_STORE_NAME };
}

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

// --- auth middleware ---
function authMiddleware(requiredRoles = []) {
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
  const { phone, name, vehicle, vehicleNo, password } = req.body || {};
  const beneficiaryCode = String((req.body || {}).beneficiaryCode || '').trim().toUpperCase();
  if (!phone || !name) return res.status(400).json({ error: 'phone and name required' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  if (!beneficiaryCode || !BENEFICIARY_CODE_LIMITS[beneficiaryCode]) {
    return res.status(400).json({ error: 'Valid beneficiaryCode required' });
  }
  try {
    let user = await User.findOne({ username: phone, role: 'delivery' });
    const existingCode = user && user.meta ? String(user.meta.beneficiaryCode || '').trim().toUpperCase() : '';

    if (user && existingCode && existingCode !== beneficiaryCode) {
      return res.status(400).json({ error: 'This phone is already registered with another beneficiary code' });
    }

    if (!user) {
      const currentCount = await User.countDocuments({ role: 'delivery', 'meta.beneficiaryCode': beneficiaryCode });
      const limit = BENEFICIARY_CODE_LIMITS[beneficiaryCode];
      if (currentCount >= limit) {
        return res.status(400).json({ error: `Beneficiary code limit reached (${limit} users)` });
      }
    }

    if (!user) {
      user = new User({
        id: 'u_' + Date.now(),
        username: phone,
        passwordHash: sha256(password),
        role: 'delivery',
        name,
        meta: { vehicle, vehicleNo, beneficiaryCode }
      });
      await user.save();
    } else {
      user.name = name;
      user.passwordHash = sha256(password);
      user.meta = user.meta || {};
      user.meta.vehicle = vehicle;
      user.meta.vehicleNo = vehicleNo;
      user.meta.beneficiaryCode = beneficiaryCode;
      await user.save();
    }
    const token = generateToken();
    const newToken = new Token({ token, userId: user.id, createdAt: new Date().toISOString() });
    await newToken.save();
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name, beneficiaryCode } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/verify-delivery-reset', async (req, res) => {
  const { phone, oldPassword } = req.body || {};
  const beneficiaryCode = String((req.body || {}).beneficiaryCode || '').trim().toUpperCase();
  if (!phone) return res.status(400).json({ error: 'phone required' });
  if (!oldPassword && !beneficiaryCode) return res.status(400).json({ error: 'oldPassword or beneficiaryCode required' });

  try {
    const user = await User.findOne({ username: phone, role: 'delivery' });
    if (!user) return res.status(404).json({ error: 'User not found' });

    let verified = false;
    if (oldPassword && user.passwordHash === sha256(oldPassword)) {
      verified = true;
    }

    if (!verified && beneficiaryCode) {
      const userCode = user && user.meta ? String(user.meta.beneficiaryCode || '').trim().toUpperCase() : '';
      if (userCode && userCode === beneficiaryCode) verified = true;
    }

    if (!verified) return res.status(401).json({ error: 'Verification failed' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/reset-delivery-password', async (req, res) => {
  const { phone, newPassword } = req.body || {};
  if (!phone || !newPassword) return res.status(400).json({ error: 'phone and newPassword required' });
  if (String(newPassword).length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });

  try {
    const user = await User.findOne({ username: phone, role: 'delivery' });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.passwordHash = sha256(String(newPassword));
    await user.save();
    res.json({ ok: true });
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

    const { storeKey, storeName } = getEffectiveProductOverrideStoreMeta(req);
    const nextData = { ...data, storeKey, storeName };

    const stock = normalizeStockNumber(nextData.availableStock);
    if (stock !== null) {
      nextData.availableStock = stock;
      const qtyLimit = Number(nextData.qtyLimit);
      if (!Number.isFinite(qtyLimit) || qtyLimit > stock) {
        nextData.qtyLimit = stock;
      }
      if (stock <= 0) {
        nextData.outOfStock = true;
        nextData.qtyLimit = 0;
      }
    } else if (typeof nextData.qtyLimit !== 'undefined') {
      const qtyLimit = normalizeStockNumber(nextData.qtyLimit);
      if (qtyLimit === null) {
        delete nextData.qtyLimit;
      } else {
        nextData.qtyLimit = qtyLimit;
      }
    }

    const product = new Product(nextData);
    await product.save();
    globalLastUpdate = Date.now();
    res.json({ ok: true, product });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/products/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    const product = await Product.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!product) return res.status(404).json({ error: 'Not found' });
    globalLastUpdate = Date.now();
    res.json({ ok: true, product });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/products/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    await Product.deleteOne({ id: req.params.id });
    globalLastUpdate = Date.now();
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
    const orderTypeText = [data.orderMode, data.orderType, data.channel, data.businessType]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    const isB2B = orderTypeText.includes('b2b');
    const inferredStoreName = normalizeStoreName(
      (data.darkStore && data.darkStore.name) || data.darkStoreName || ''
    );
    const inferredStoreKey = toStoreKey(inferredStoreName || (data.darkStore && data.darkStore.id) || data.darkStoreId || '') || DEFAULT_STORE_KEY;
    const inferredStoreLabel = inferredStoreName || inferredStoreKey;

    const id = 'ORD' + Date.now().toString().slice(-8);
    const order = new Order({
      id,
      date: new Date().toLocaleString(),
      items: data.items,
      userName: data.userName || '',
      userPhone: data.userPhone || '',
      receiverPhone: data.receiverPhone || '',
      deliveryTimeSlot: data.deliveryTimeSlot || '',
      location: data.location || null,
      subtotal: data.subtotal || 0,
      fees: data.fees || {},
      discount: data.discount || 0,
      total: data.total || 0,
      darkStoreId: data.darkStoreId || '',
      darkStoreName: data.darkStoreName || '',
      darkStore: data.darkStore || null,
      userEmail: data.userEmail || '',
      paymentMethod: data.paymentMethod || '',
      orderMode: data.orderMode || '',
      orderType: data.orderType || '',
      channel: data.channel || '',
      businessType: data.businessType || '',
      status: 'pending',
      history: [{ status: 'pending', at: new Date().toISOString() }]
    });
    await order.save();

    const stockUpdates = await decrementOrderItemsStock({
      items: data.items,
      isB2B,
      storeKey: inferredStoreKey,
      storeName: inferredStoreLabel
    });

    if (stockUpdates.length > 0) {
      globalLastUpdate = Date.now();
    }

    res.json({ ok: true, order, stockUpdates });
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

// Update delivery partner location for an order
app.put('/api/orders/:id/delivery-location', authMiddleware(['delivery']), async (req, res) => {
  const { latitude, longitude, name } = req.body || {};
  if (!latitude || !longitude) return res.status(400).json({ error: 'latitude and longitude required' });
  
  try {
    const order = await Order.findOne({ id: req.params.id });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    
    // Check if this delivery user is assigned to this order
    if (!order.assignedTo || order.assignedTo.id !== req.user.id) {
      return res.status(403).json({ error: 'Not assigned to this order' });
    }
    
    order.deliveryPartnerLocation = {
      latitude: parseFloat(latitude),
      longitude: parseFloat(longitude),
      name: name || req.user.name,
      lastUpdated: new Date().toISOString()
    };
    
    await order.save();
    res.json({ ok: true, location: order.deliveryPartnerLocation });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/:id/delivery-location', async (req, res) => {
  try {
    const order = await Order.findOne({ id: req.params.id });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    
    if (!order.deliveryPartnerLocation) {
      return res.status(404).json({ error: 'Location not available' });
    }
    
    res.json({ location: order.deliveryPartnerLocation });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get orders for a specific user (by phone)
app.get('/api/orders/user/:phone', async (req, res) => {
  const phone = req.params.phone;
  if (!phone) return res.status(400).json({ error: 'phone required' });
  
  try {
    const orders = await Order.find({ userPhone: phone }).sort({ date: -1 });
    res.json({ orders });
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
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    let promos = await Promo.find(getStoreQuery(storeKey));

    if (storeKey && promos.length === 0) {
      promos = await Promo.find(getGlobalStoreQuery());
    }

    res.json({ promos, store: storeName || null, storeKey: storeKey || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/promos', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    await Promo.deleteMany(getStoreQuery(storeKey));
    const promos = Array.isArray(req.body) ? req.body : (req.body.promos || []);

    if (promos.length > 0) {
      const docs = promos.map(p => ({ ...p, storeKey: storeKey || null, storeName: storeName || null }));
      await Promo.insertMany(docs);
    }

    globalLastUpdate = Date.now();
    res.json({ ok: true, promos, store: storeName || null, storeKey: storeKey || null });
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
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    const storeDocId = storeKey ? `fees__${storeKey}` : 'fees';

    let feeDoc = await Fee.findOne({ _id: storeDocId });
    if (!feeDoc && storeKey) {
      feeDoc = await Fee.findOne({ _id: 'fees' });
    }

    res.json({ fees: feeDoc ? feeDoc.value : {}, store: storeName || null, storeKey: storeKey || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/fees', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    const fees = req.body || {};
    const storeDocId = storeKey ? `fees__${storeKey}` : 'fees';

    await Fee.findOneAndUpdate(
      { _id: storeDocId },
      { _id: storeDocId, storeKey: storeKey || null, storeName: storeName || null, value: fees },
      { upsert: true }
    );

    globalLastUpdate = Date.now();
    res.json({ ok: true, fees, store: storeName || null, storeKey: storeKey || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Product Overrides (price/image/outOfStock) ---
app.get('/api/product-overrides', async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    let resolvedStoreKey = null;
    let resolvedStoreName = null;
    let overrides = [];

    if (storeKey) {
      overrides = await ProductOverride.find({ storeKey });
      if (overrides.length > 0) {
        resolvedStoreKey = storeKey;
        resolvedStoreName = storeName || (overrides[0] && overrides[0].storeName) || storeKey;
      }
    }

    if (overrides.length === 0) {
      overrides = await ProductOverride.find({ storeKey: DEFAULT_STORE_KEY });
      if (overrides.length > 0) {
        resolvedStoreKey = DEFAULT_STORE_KEY;
        resolvedStoreName = DEFAULT_STORE_NAME;
      }
    }

    if (overrides.length === 0) {
      overrides = await ProductOverride.find(getGlobalStoreQuery());
      if (overrides.length > 0) {
        resolvedStoreKey = null;
        resolvedStoreName = null;
      }
    }

    const overridesObj = {};
    overrides.forEach(o => {
      overridesObj[o.id] = sanitizeOverrideDoc(o);
    });

    res.json({ overrides: overridesObj, store: resolvedStoreName, storeKey: resolvedStoreKey });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/product-overrides', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getEffectiveProductOverrideStoreMeta(req);
    const body = req.body || {};
    const overrides = (!Array.isArray(body) && body && typeof body === 'object' && body.overrides && typeof body.overrides === 'object')
      ? body.overrides
      : body;

    await ProductOverride.deleteMany({ storeKey });

    const docs = Object.keys(overrides).map(id => ({ id, ...sanitizeIncomingOverrideValue(overrides[id]), storeKey, storeName }));
    if (docs.length > 0) {
      await ProductOverride.insertMany(docs);
    }

    globalLastUpdate = Date.now();
    res.json({ ok: true, overrides, store: storeName, storeKey });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/product-overrides/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getEffectiveProductOverrideStoreMeta(req);
    const id = req.params.id;
    const update = req.body || {};
    const query = { id, storeKey };
    const nextValue = { ...sanitizeIncomingOverrideValue(update), id, storeKey, storeName };
    const override = await ProductOverride.findOneAndUpdate(query, nextValue, { upsert: true, new: true });
    globalLastUpdate = Date.now();
    res.json({ ok: true, override, store: storeName, storeKey });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- B2B Fees ---
app.get('/api/b2b/fees', async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    const storeDocId = storeKey ? `b2b_fees__${storeKey}` : 'b2b_fees';

    let feeDoc = await B2BFee.findOne({ _id: storeDocId });
    if (!feeDoc && storeKey) {
      feeDoc = await B2BFee.findOne({ _id: 'b2b_fees' });
    }

    res.json({ fees: feeDoc ? feeDoc.value : {}, store: storeName || null, storeKey: storeKey || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/b2b/fees', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    const fees = req.body || {};
    const storeDocId = storeKey ? `b2b_fees__${storeKey}` : 'b2b_fees';

    await B2BFee.findOneAndUpdate(
      { _id: storeDocId },
      { _id: storeDocId, storeKey: storeKey || null, storeName: storeName || null, value: fees },
      { upsert: true }
    );

    globalLastUpdate = Date.now();
    res.json({ ok: true, fees, store: storeName || null, storeKey: storeKey || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- B2B Promos ---
app.get('/api/b2b/promos', async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    let promos = await B2BPromo.find(getStoreQuery(storeKey));

    if (storeKey && promos.length === 0) {
      promos = await B2BPromo.find(getGlobalStoreQuery());
    }

    res.json({ promos, store: storeName || null, storeKey: storeKey || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/b2b/promos', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    await B2BPromo.deleteMany(getStoreQuery(storeKey));
    const promos = Array.isArray(req.body) ? req.body : (req.body.promos || []);

    if (promos.length > 0) {
      const docs = promos.map(p => ({ ...p, storeKey: storeKey || null, storeName: storeName || null }));
      await B2BPromo.insertMany(docs);
    }

    globalLastUpdate = Date.now();
    res.json({ ok: true, promos, store: storeName || null, storeKey: storeKey || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- B2B Product Overrides ---
app.get('/api/b2b/product-overrides', async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    let resolvedStoreKey = null;
    let resolvedStoreName = null;
    let overrides = [];

    if (storeKey) {
      overrides = await B2BProductOverride.find({ storeKey });
      if (overrides.length > 0) {
        resolvedStoreKey = storeKey;
        resolvedStoreName = storeName || (overrides[0] && overrides[0].storeName) || storeKey;
      }
    }

    if (overrides.length === 0) {
      overrides = await B2BProductOverride.find({ storeKey: DEFAULT_STORE_KEY });
      if (overrides.length > 0) {
        resolvedStoreKey = DEFAULT_STORE_KEY;
        resolvedStoreName = DEFAULT_STORE_NAME;
      }
    }

    if (overrides.length === 0) {
      overrides = await B2BProductOverride.find(getGlobalStoreQuery());
      if (overrides.length > 0) {
        resolvedStoreKey = null;
        resolvedStoreName = null;
      }
    }

    const overridesObj = {};
    overrides.forEach(o => {
      overridesObj[o.id] = sanitizeOverrideDoc(o);
    });

    res.json({ overrides: overridesObj, store: resolvedStoreName, storeKey: resolvedStoreKey });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/b2b/product-overrides', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getEffectiveProductOverrideStoreMeta(req);
    const body = req.body || {};
    const overrides = (!Array.isArray(body) && body && typeof body === 'object' && body.overrides && typeof body.overrides === 'object')
      ? body.overrides
      : body;

    await B2BProductOverride.deleteMany({ storeKey });

    const docs = Object.keys(overrides).map(id => ({ id, ...sanitizeIncomingOverrideValue(overrides[id]), storeKey, storeName }));
    if (docs.length > 0) {
      await B2BProductOverride.insertMany(docs);
    }

    globalLastUpdate = Date.now();
    res.json({ ok: true, overrides, store: storeName, storeKey });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- B2B Product Catalog ---
app.get('/api/b2b/products', async (req, res) => {
  try {
    const { storeKey, storeName } = getStoreMetaFromRequest(req);
    let resolvedStoreKey = null;
    let resolvedStoreName = null;
    let products = [];

    if (storeKey) {
      products = await B2BProduct.find({ storeKey });
      if (products.length > 0) {
        resolvedStoreKey = storeKey;
        resolvedStoreName = storeName || (products[0] && products[0].storeName) || storeKey;
      }
    }

    if (products.length === 0) {
      products = await B2BProduct.find({ storeKey: DEFAULT_STORE_KEY });
      if (products.length > 0) {
        resolvedStoreKey = DEFAULT_STORE_KEY;
        resolvedStoreName = DEFAULT_STORE_NAME;
      }
    }

    if (products.length === 0) {
      products = await B2BProduct.find(getGlobalStoreQuery());
      if (products.length > 0) {
        resolvedStoreKey = null;
        resolvedStoreName = null;
      }
    }

    const cleaned = products.map(p => sanitizeOverrideDoc(p));
    res.json({ products: cleaned, store: resolvedStoreName, storeKey: resolvedStoreKey });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/b2b/products', authMiddleware(['admin']), async (req, res) => {
  try {
    const { storeKey, storeName } = getEffectiveProductOverrideStoreMeta(req);
    const body = req.body || {};
    const products = Array.isArray(body) ? body : (Array.isArray(body.products) ? body.products : []);

    await B2BProduct.deleteMany({ storeKey });

    if (products.length > 0) {
      const docs = products.map(p => ({ ...sanitizeIncomingOverrideValue(p), id: p.id, storeKey, storeName })).filter(p => !!p.id);
      if (docs.length > 0) await B2BProduct.insertMany(docs);
    }

    globalLastUpdate = Date.now();
    res.json({ ok: true, products, store: storeName, storeKey });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Dark Store Locations (used by Admin Panel) ---
app.get('/api/dark-stores', async (req, res) => {
  try {
    const locations = await DarkStoreLocation.find({}).sort({ createdAt: 1, name: 1, id: 1 });
    res.json({ locations });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/dark-stores', authMiddleware(['admin']), async (req, res) => {
  try {
    const locations = Array.isArray(req.body)
      ? req.body
      : (Array.isArray(req.body && req.body.locations) ? req.body.locations : []);

    const cleaned = locations
      .map((loc) => {
        const src = loc && typeof loc === 'object' ? loc : {};
        const id = (src.id || '').toString().trim();
        const name = normalizeStoreName(src.name || '');
        if (!id || !name) return null;

        const next = {
          id,
          name,
          address: (src.address || '').toString().trim(),
          createdAt: src.createdAt || new Date().toISOString(),
        };

        const lat = Number(src.latitude);
        const lng = Number(src.longitude);
        if (Number.isFinite(lat) && Number.isFinite(lng)) {
          next.latitude = lat;
          next.longitude = lng;
        }

        return next;
      })
      .filter(Boolean);

    await DarkStoreLocation.deleteMany({});
    if (cleaned.length > 0) {
      await DarkStoreLocation.insertMany(cleaned, { ordered: true });
    }

    globalLastUpdate = Date.now();
    res.json({ ok: true, locations: cleaned });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Last update timestamp for polling
app.get('/api/last-update', (req, res) => {
  res.json({ lastUpdate: globalLastUpdate });
});

// Receiver mobile logging (used by storefront when receiver phone is entered)
app.post('/api/receiver-mobile', (req, res) => {
  const { userPhone, receiverPhone } = req.body || {};
  if (!receiverPhone) return res.status(400).json({ error: 'receiverPhone required' });
  // Log for operational visibility; no persistent storage needed
  console.log(`[receiver-mobile] user=${userPhone || 'guest'} receiver=${receiverPhone}`);
  res.json({ ok: true });
});


app.post('/upload-image', (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err) {
      const isMulterError = err instanceof multer.MulterError;
      const status = isMulterError ? 400 : 500;
      return res.status(status).json({ error: err.message || 'Image upload failed' });
    }

    try {
      const hasCloudinaryConfig =
        !!CLOUDINARY_CLOUD_NAME &&
        !!CLOUDINARY_API_KEY &&
        !!CLOUDINARY_API_SECRET;

      if (!hasCloudinaryConfig) {
        return res.status(500).json({
          error: 'Cloudinary environment variables are not configured',
        });
      }

      if (!req.file) {
        return res.status(400).json({ error: 'image file is required' });
      }

      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'grozo_products', resource_type: 'image' },
          (uploadErr, uploadResult) => {
            if (uploadErr) return reject(uploadErr);
            resolve(uploadResult);
          }
        );
        stream.end(req.file.buffer);
      });

      return res.json({ secure_url: result.secure_url });
    } catch (uploadError) {
      console.error('Cloudinary upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to upload image' });
    }
  });
});

// fallback
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Frontend helper endpoints ---
const FRONTEND_LINKS = {
  home: process.env.FRONTEND_LINKS_HOME || 'https://grozo.online/',
  admin: process.env.FRONTEND_LINKS_ADMIN || 'https://grozo-admin.netlify.app/',
  dashboard: process.env.FRONTEND_LINKS_DASHBOARD || 'https://grozo-dashboard.netlify.app/',
  delivery: process.env.FRONTEND_LINKS_DELIVERY || 'https://grozo-deliverypartner.netlify.app/'
};

app.get('/api/frontend-links', (req, res) => res.json(FRONTEND_LINKS));

// --- Google sign-in verification endpoint ---
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '1054365989272-e3t05dqp8k4vf3slii9ofdiujsdq7js0.apps.googleusercontent.com';

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
