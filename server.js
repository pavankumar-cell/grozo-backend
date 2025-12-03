const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'db.json');
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
// CORS middleware: allow only our known frontends (keeps '*' out for security)
const ALLOWED_FRONTENDS = [
  'https://grozo-home.netlify.app',
  'https://grozo-admin.netlify.app',
  'https://grozo-dashboard.netlify.app',
  'https://grozo-deliverypartner.netlify.app'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_FRONTENDS.includes(origin.replace(/\/$/, ''))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function initDB() {
  if (!fs.existsSync(DB_PATH)) {
    const initial = { products: [], orders: [], users: [], tokens: [], fees: {}, promos: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2));
  }
}

function readDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8') || '{}';
    return JSON.parse(raw);
  } catch (e) {
    return { products: [], orders: [], users: [], tokens: [], fees: {}, promos: [] };
  }
}

function writeDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

// initialize DB & default admin
initDB();
const db = readDB();
db.products = db.products || [];
db.orders = db.orders || [];
db.users = db.users || [];
db.tokens = db.tokens || [];
db.fees = db.fees || {};
db.promos = db.promos || [];

if (!db.users.some(u => u.role === 'admin')) {
  const admin = { id: 'u_admin', username: 'admin', passwordHash: sha256('admin123'), role: 'admin', name: 'Administrator' };
  db.users.push(admin);
  writeDB(db);
  console.log('Created default admin user: username=admin password=admin123 (change immediately)');
}

// --- auth middleware ---
function authMiddleware(requiredRoles = []) {
  return (req, res, next) => {
    const auth = req.headers.authorization || '';
    const match = auth.match(/^Bearer\s+(\S+)$/i);
    if (!match) return res.status(401).json({ error: 'Missing token' });
    const token = match[1];
    const db = readDB();
    const t = db.tokens.find(x => x.token === token);
    if (!t) return res.status(401).json({ error: 'Invalid token' });
    const user = db.users.find(u => u.id === t.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (requiredRoles.length && !requiredRoles.includes(user.role)) return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  };
}

// --- Auth routes ---
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const db = readDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.passwordHash !== sha256(password)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = generateToken();
  db.tokens.push({ token, userId: user.id, createdAt: new Date().toISOString() });
  writeDB(db);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
});

// Delivery registration (creates delivery user if not exists)
app.post('/api/auth/register-delivery', (req, res) => {
  const { phone, name, vehicle, vehicleNo } = req.body || {};
  if (!phone || !name) return res.status(400).json({ error: 'phone and name required' });
  const db = readDB();
  let user = db.users.find(u => u.username === phone && u.role === 'delivery');
  if (!user) {
    user = { id: 'u_' + Date.now(), username: phone, passwordHash: sha256(phone.slice(-4) || '0000'), role: 'delivery', name, meta: { vehicle, vehicleNo } };
    db.users.push(user);
    writeDB(db);
  }
  const token = generateToken();
  db.tokens.push({ token, userId: user.id, createdAt: new Date().toISOString() });
  writeDB(db);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
});

// --- Products ---
app.get('/api/products', (req, res) => {
  const db = readDB();
  res.json({ products: db.products || [] });
});

app.get('/api/products/:id', (req, res) => {
  const db = readDB();
  const p = db.products.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Product not found' });
  res.json(p);
});

app.post('/api/products', authMiddleware(['admin']), (req, res) => {
  const data = req.body || {};
  if (!data.id || !data.name) return res.status(400).json({ error: 'id and name required' });
  const db = readDB();
  if (db.products.find(x => x.id === data.id)) return res.status(400).json({ error: 'Product id already exists' });
  db.products.push(data);
  writeDB(db);
  res.json({ ok: true, product: data });
});

app.put('/api/products/:id', authMiddleware(['admin']), (req, res) => {
  const db = readDB();
  const idx = db.products.findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.products[idx] = Object.assign({}, db.products[idx], req.body);
  writeDB(db);
  res.json({ ok: true, product: db.products[idx] });
});

app.delete('/api/products/:id', authMiddleware(['admin']), (req, res) => {
  const db = readDB();
  db.products = db.products.filter(x => x.id !== req.params.id);
  writeDB(db);
  res.json({ ok: true });
});

// --- Orders ---
app.post('/api/orders', (req, res) => {
  const data = req.body || {};
  if (!data.items || !Array.isArray(data.items) || data.items.length === 0) return res.status(400).json({ error: 'items required' });
  const db = readDB();
  const id = 'ORD' + Date.now().toString().slice(-8);
  const order = {
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
  };
  db.orders.push(order);
  writeDB(db);
  // for realtime in-browser flows, write a last-dispatch like key isn't needed here; frontends can watch /api/orders
  res.json({ ok: true, order });
});

app.get('/api/orders', authMiddleware(['admin','delivery']), (req, res) => {
  const db = readDB();
  res.json({ orders: db.orders || [] });
});

app.get('/api/orders/:id', authMiddleware(['admin','delivery']), (req, res) => {
  const db = readDB();
  const o = db.orders.find(x => x.id === req.params.id);
  if (!o) return res.status(404).json({ error: 'Order not found' });
  res.json(o);
});

app.put('/api/orders/:id/status', authMiddleware(['admin','delivery']), (req, res) => {
  const { status } = req.body || {};
  if (!status) return res.status(400).json({ error: 'status required' });
  const db = readDB();
  const idx = db.orders.findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Order not found' });
  db.orders[idx].status = status;
  db.orders[idx].history = db.orders[idx].history || [];
  db.orders[idx].history.push({ status, by: req.user.username, at: new Date().toISOString() });
  writeDB(db);
  res.json({ ok: true, order: db.orders[idx] });
});

app.post('/api/orders/:id/assign-delivery', authMiddleware(['admin']), (req, res) => {
  const { deliveryUserId } = req.body || {};
  if (!deliveryUserId) return res.status(400).json({ error: 'deliveryUserId required' });
  const db = readDB();
  const order = db.orders.find(x => x.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const deliveryUser = db.users.find(u => u.id === deliveryUserId && u.role === 'delivery');
  if (!deliveryUser) return res.status(404).json({ error: 'Delivery user not found' });
  order.assignedTo = { id: deliveryUser.id, username: deliveryUser.username, name: deliveryUser.name };
  order.status = 'dispatched';
  order.history = order.history || [];
  order.history.push({ status: 'dispatched', by: req.user.username, at: new Date().toISOString() });
  writeDB(db);
  res.json({ ok: true, order });
});

// Find order by dispatch code (public)
app.get('/api/orders/dispatch/:code', (req, res) => {
  const code = (req.params.code || '').toString();
  if (!code) return res.status(400).json({ error: 'code required' });
  const db = readDB();
  const order = (db.orders || []).find(o => o.dispatch && (o.dispatch.code === code || (o.dispatch.code||'').toString() === code));
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json({ order });
});

// Generic order update (admin/delivery) - merges provided fields into order
app.put('/api/orders/:id', authMiddleware(['admin','delivery']), (req, res) => {
  const db = readDB();
  const idx = db.orders.findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Order not found' });
  const toMerge = req.body || {};
  // prevent changing id
  delete toMerge.id;
  db.orders[idx] = Object.assign({}, db.orders[idx], toMerge);
  db.orders[idx].history = db.orders[idx].history || [];
  db.orders[idx].history.push({ updatedBy: req.user.username, at: new Date().toISOString(), changes: Object.keys(toMerge) });
  writeDB(db);
  res.json({ ok: true, order: db.orders[idx] });
});

// promos
app.get('/api/promos', (req, res) => {
  const db = readDB();
  res.json({ promos: db.promos || [] });
});

app.put('/api/promos', authMiddleware(['admin']), (req, res) => {
  const db = readDB();
  db.promos = Array.isArray(req.body) ? req.body : (req.body.promos || []);
  writeDB(db);
  res.json({ ok: true, promos: db.promos });
});

// --- Users list (admin) and deliveries (public list) ---
app.get('/api/delivery-partners', authMiddleware(['admin']), (req, res) => {
  const db = readDB();
  const deliveries = db.users.filter(u => u.role === 'delivery');
  res.json({ deliveries });
});

app.get('/api/me', authMiddleware(['admin','delivery']), (req, res) => {
  res.json({ user: req.user });
});

// --- simple admin endpoints for fees/promos ---
app.get('/api/fees', (req, res) => {
  const db = readDB();
  res.json({ fees: db.fees || {} });
});

app.put('/api/fees', authMiddleware(['admin']), (req, res) => {
  const db = readDB();
  db.fees = Object.assign({}, db.fees || {}, req.body || {});
  writeDB(db);
  res.json({ ok: true, fees: db.fees });
});

// fallback
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Frontend helper endpoints ---
const FRONTEND_LINKS = {
  home: 'https://grozo-home.netlify.app/',
  admin: 'https://grozo-admin.netlify.app/',
  dashboard: 'https://grozo-dashboard.netlify.app/',
  delivery: 'https://grozo-deliverypartner.netlify.app/'
};

app.get('/api/frontend-links', (req, res) => res.json(FRONTEND_LINKS));

app.get('/go/home', (req, res) => res.redirect(FRONTEND_LINKS.home));
app.get('/go/admin', (req, res) => res.redirect(FRONTEND_LINKS.admin));
app.get('/go/dashboard', (req, res) => res.redirect(FRONTEND_LINKS.dashboard));
app.get('/go/delivery', (req, res) => res.redirect(FRONTEND_LINKS.delivery));

app.listen(PORT, () => console.log(`Backend listening on http://localhost:${PORT}`));
