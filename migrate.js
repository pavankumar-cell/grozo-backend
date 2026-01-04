<<<<<<< HEAD
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'your_mongodb_connection_string_here';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define schemas (same as server.js)
const productSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  price: Number,
});

const orderSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  date: String,
  items: Array,
  userName: String,
  userPhone: String,
  receiverPhone: String,
  location: Object,
  subtotal: Number,
  fees: Object,
  discount: Number,
  total: Number,
  status: String,
  history: Array,
  // Delivery partner information
  pickedUpByName: String,
  pickedUpByPhone: String,
  pickedUpAt: String,
  deliveredByName: String,
  deliveredByPhone: String,
  deliveredAt: String,
  deliveryPartnerVehicle: String,
  deliveryPartnerVehicleNo: String,
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
  _id: String,
  value: Object,
});

const promoSchema = new mongoose.Schema({
  id: String,
}, { strict: false });

const productOverrideSchema = new mongoose.Schema({
  id: String,
}, { strict: false });

const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);
const Fee = mongoose.model('Fee', feeSchema);
const Promo = mongoose.model('Promo', promoSchema);
const ProductOverride = mongoose.model('ProductOverride', productOverrideSchema);

// Read db.json
const DB_PATH = path.join(__dirname, 'db.json');
const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));

async function migrate() {
  try {
    // Migrate products
    if (db.products && db.products.length) {
      await Product.insertMany(db.products);
      console.log('Migrated products');
    }

    // Migrate orders
    if (db.orders && db.orders.length) {
      await Order.insertMany(db.orders);
      console.log('Migrated orders');
    }

    // Migrate users
    if (db.users && db.users.length) {
      await User.insertMany(db.users);
      console.log('Migrated users');
    }

    // Migrate tokens
    if (db.tokens && db.tokens.length) {
      await Token.insertMany(db.tokens);
      console.log('Migrated tokens');
    }

    // Migrate fees
    if (db.fees) {
      await Fee.create({ _id: 'fees', value: db.fees });
      console.log('Migrated fees');
    }

    // Migrate promos
    if (db.promos && db.promos.length) {
      await Promo.insertMany(db.promos);
      console.log('Migrated promos');
    }

    // Migrate productOverrides
    if (db.productOverrides) {
      const overrides = Object.keys(db.productOverrides).map(id => ({ id, ...db.productOverrides[id] }));
      await ProductOverride.insertMany(overrides);
      console.log('Migrated productOverrides');
    }

    console.log('Migration complete');
    process.exit(0);
  } catch (err) {
    console.error('Migration error:', err);
    process.exit(1);
  }
}

migrate();
=======
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'your_mongodb_connection_string_here';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define schemas (same as server.js)
const productSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  price: Number,
});

const orderSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  date: String,
  items: Array,
  userName: String,
  userPhone: String,
  receiverPhone: String,
  location: Object,
  subtotal: Number,
  fees: Object,
  discount: Number,
  total: Number,
  status: String,
  history: Array,
  // Delivery partner information
  pickedUpByName: String,
  pickedUpByPhone: String,
  pickedUpAt: String,
  deliveredByName: String,
  deliveredByPhone: String,
  deliveredAt: String,
  deliveryPartnerVehicle: String,
  deliveryPartnerVehicleNo: String,
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
  _id: String,
  value: Object,
});

const promoSchema = new mongoose.Schema({
  id: String,
}, { strict: false });

const productOverrideSchema = new mongoose.Schema({
  id: String,
}, { strict: false });

const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);
const Fee = mongoose.model('Fee', feeSchema);
const Promo = mongoose.model('Promo', promoSchema);
const ProductOverride = mongoose.model('ProductOverride', productOverrideSchema);

// Read db.json
const DB_PATH = path.join(__dirname, 'db.json');
const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));

async function migrate() {
  try {
    // Migrate products
    if (db.products && db.products.length) {
      await Product.insertMany(db.products);
      console.log('Migrated products');
    }

    // Migrate orders
    if (db.orders && db.orders.length) {
      await Order.insertMany(db.orders);
      console.log('Migrated orders');
    }

    // Migrate users
    if (db.users && db.users.length) {
      await User.insertMany(db.users);
      console.log('Migrated users');
    }

    // Migrate tokens
    if (db.tokens && db.tokens.length) {
      await Token.insertMany(db.tokens);
      console.log('Migrated tokens');
    }

    // Migrate fees
    if (db.fees) {
      await Fee.create({ _id: 'fees', value: db.fees });
      console.log('Migrated fees');
    }

    // Migrate promos
    if (db.promos && db.promos.length) {
      await Promo.insertMany(db.promos);
      console.log('Migrated promos');
    }

    // Migrate productOverrides
    if (db.productOverrides) {
      const overrides = Object.keys(db.productOverrides).map(id => ({ id, ...db.productOverrides[id] }));
      await ProductOverride.insertMany(overrides);
      console.log('Migrated productOverrides');
    }

    console.log('Migration complete');
    process.exit(0);
  } catch (err) {
    console.error('Migration error:', err);
    process.exit(1);
  }
}

migrate();
>>>>>>> 385f730d1626eb8664afd2af6afe0986058a6022
