const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const paypal = require('@paypal/checkout-server-sdk');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: ['https://delicute.onrender.com', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// File Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Environment Variables Validation
const requiredEnvVars = [
  'DB_NAME',
  'DB_HOST',
  'DB_USER',
  'DB_PASSWORD',
  'DB_PORT',
  'JWT_SECRET',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'EMAIL_USER',
  'EMAIL_PASS',
  'GOOGLE_PAY_MERCHANT_ID',
  'PHONEPE_MERCHANT_ID',
  'PHONEPE_SALT_KEY',
  'PAYPAL_CLIENT_ID',
  'PAYPAL_CLIENT_SECRET'
];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing environment variable: ${envVar}`);
    process.exit(1);
  }
}

const {
  DB_NAME,
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_PORT,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  EMAIL_USER,
  EMAIL_PASS,
  GOOGLE_PAY_MERCHANT_ID,
  PHONEPE_MERCHANT_ID,
  PHONEPE_SALT_KEY,
  PHONEPE_SALT_INDEX,
  PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET,
  PORT = 3000,
  CLIENT_URL = 'http://localhost:3000',
  NODE_ENV = 'development'
} = process.env;

// Database Connection
const pool = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// PayPal Client Setup
const paypalEnvironment = NODE_ENV === 'production'
  ? new paypal.core.LiveEnvironment(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET)
  : new paypal.core.SandboxEnvironment(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET);
const paypalClient = new paypal.core.PayPalHttpClient(paypalEnvironment);

// Initialize Database
async function initializeDatabase() {
  try {
    console.log('Attempting to connect to MySQL...');
    const connection = await pool.getConnection();
    console.log('✅ Connected to MySQL database');

    // Check if tables exist
    const [existingTables] = await connection.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = ? 
      AND table_name IN ('users', 'menu_items', 'offers', 'orders', 'restaurant_status', 'coupons', 'contact_messages', 'addresses')
    `, [DB_NAME]);
    const tableNames = existingTables.map(row => row.table_name);

    // Create users table
    if (!tableNames.includes('users')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255),
          email VARCHAR(255) UNIQUE NOT NULL,
          phone VARCHAR(20),
          password VARCHAR(255),
          is_admin BOOLEAN DEFAULT FALSE,
          is_blocked BOOLEAN DEFAULT FALSE,
          profile_image VARCHAR(255),
          reset_otp VARCHAR(6),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created users table');
    }

    // Create addresses table (before orders due to foreign key dependency)
    if (!tableNames.includes('addresses')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS addresses (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT,
          full_name VARCHAR(255) NOT NULL,
          mobile VARCHAR(20) NOT NULL,
          house_number VARCHAR(100) NOT NULL,
          street VARCHAR(255) NOT NULL,
          landmark VARCHAR(255),
          pincode VARCHAR(10) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `);
      console.log('✅ Created addresses table');
    }

    // Create menu_items table
    if (!tableNames.includes('menu_items')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS menu_items (
          id INT AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          category VARCHAR(100) NOT NULL,
          price INT NOT NULL,
          description TEXT,
          image VARCHAR(255),
          rating INT DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created menu_items table');
    }

    // Create offers table
    if (!tableNames.includes('offers')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS offers (
          id INT AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          description TEXT,
          price INT NOT NULL,
          image VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created offers table');
    }

    // Create orders table (after addresses due to foreign key dependency)
    if (!tableNames.includes('orders')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS orders (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT,
          items JSON NOT NULL,
          total INT NOT NULL,
          status VARCHAR(50) DEFAULT 'Pending',
          payment_status VARCHAR(50) DEFAULT 'Pending',
          payment_method VARCHAR(50),
          payment_details JSON,
          coupon VARCHAR(50),
          discount INT DEFAULT 0,
          delivery_address_id INT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id),
          FOREIGN KEY (delivery_address_id) REFERENCES addresses(id)
        )
      `);
      console.log('✅ Created orders table');
    }

    // Create restaurant_status table
    if (!tableNames.includes('restaurant_status')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS restaurant_status (
          id INT AUTO_INCREMENT PRIMARY KEY,
          status VARCHAR(50) DEFAULT 'Closed',
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created restaurant_status table');
      
      // Insert initial status
      const [statusCheck] = await connection.query('SELECT * FROM restaurant_status WHERE id = 1');
      if (statusCheck.length === 0) {
        await connection.query(`
          INSERT INTO restaurant_status (id, status) 
          VALUES (1, 'Closed')
        `);
        console.log('✅ Initialized restaurant_status with default value');
      }
    }

    // Create coupons table
    if (!tableNames.includes('coupons')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS coupons (
          id INT AUTO_INCREMENT PRIMARY KEY,
          code VARCHAR(50) UNIQUE NOT NULL,
          discount INT NOT NULL,
          description TEXT,
          image VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created coupons table');
    }

    // Create contact_messages table
    if (!tableNames.includes('contact_messages')) {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS contact_messages (
          id INT AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) NOT NULL,
          subject VARCHAR(255) NOT NULL,
          message TEXT NOT NULL,
          status VARCHAR(50) DEFAULT 'Pending',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created contact_messages table');
    }

    // Ensure at least one admin user exists
    const [adminCheck] = await connection.query('SELECT * FROM users WHERE is_admin = TRUE LIMIT 1');
    if (adminCheck.length === 0) {
      const defaultAdminEmail = 'admin@delicute.com';
      const defaultAdminPassword = await bcrypt.hash('Admin123!', 10);
      await connection.query(
        `INSERT INTO users (name, email, phone, password, is_admin) 
         VALUES (?, ?, ?, ?, ?) 
         ON DUPLICATE KEY UPDATE email = email`,
        ['Default Admin', defaultAdminEmail, '1234567890', defaultAdminPassword, true]
      );
      console.log('✅ Created default admin user');
    }

    console.log('✅ Database initialization completed');
    const [tables] = await connection.query("SELECT table_name FROM information_schema.tables WHERE table_schema = ?", [DB_NAME]);
    console.log('📋 Tables:', tables.map(row => row.table_name));

    connection.release();
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}
// Email Transporter Setup
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// Google OAuth Setup
const oauth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  `${CLIENT_URL}/api/auth/google/callback`
);

// Middleware to Verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.warn('No token provided for request:', req.url);
    return res.status(401).json({ error: 'Access denied, no token provided' });
  }

  if (!token.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)) {
    console.error('Malformed token received:', token);
    return res.status(403).json({ error: 'Invalid token format' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message, error.stack);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Middleware to Check Admin Privileges
async function authenticateAdmin(req, res, next) {
  try {
    const [result] = await pool.query('SELECT is_admin, is_blocked FROM users WHERE id = ?', [req.user.id]);
    const user = result[0];
    if (!user || !user.is_admin) {
      console.warn('Admin access denied for user:', req.user.id);
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (user.is_blocked) {
      console.warn('Blocked admin user attempted access:', req.user.id);
      return res.status(403).json({ error: 'Account is blocked' });
    }
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    res.status(500).json({ error: 'Invalid token or user not found' });
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admindashboard.html', authenticateToken, authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/userdashboard.html', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'userdashboard.html'));
});

app.post('/api/files/upload', authenticateToken, authenticateAdmin, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ fileUrl });
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT id, email, name, phone, profile_image, is_admin FROM users WHERE id = ?', [req.user.id]);
    const user = result[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      _id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      profileImage: user.profile_image,
      isAdmin: user.is_admin
    });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

app.put('/api/auth/update', authenticateToken, upload.single('profileImage'), async (req, res) => {
  const { name } = req.body;
  const file = req.file;
  try {
    let profileImage = null;
    if (file) {
      profileImage = `${req.protocol}://${req.get('host')}/uploads/${file.filename}`;
    }
    const [currentUser] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!currentUser[0]) return res.status(404).json({ error: 'User not found' });

    const updateFields = [];
    const values = [];
    let paramIndex = 1;

    if (name && name !== currentUser[0].name) {
      updateFields.push(`name = ?`);
      values.push(name);
    }
    if (profileImage) {
      updateFields.push(`profile_image = ?`);
      values.push(profileImage);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.user.id);
    const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
    const [result] = await pool.query(query, values);
    const [updatedUser] = await pool.query('SELECT id, email, name, phone, profile_image, is_admin FROM users WHERE id = ?', [req.user.id]);
    const user = updatedUser[0];

    res.json({
      _id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      profileImage: user.profile_image,
      isAdmin: user.is_admin
    });
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});

app.get('/api/menu', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM menu_items ORDER BY created_at DESC');
    const items = result.map(item => ({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image,
      rating: item.rating,
      created_at: item.created_at
    }));
    res.json(items);
  } catch (error) {
    console.error('Error fetching menu items:', error);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

app.get('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [id]);
    const item = result[0];
    if (!item) return res.status(404).json({ error: 'Menu item not found' });
    res.json({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image,
      rating: item.rating
    });
  } catch (error) {
    console.error('Error fetching menu item:', error);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

app.post('/api/menu', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, category, price, image, description } = req.body;
  if (!name || !category || !price) {
    return res.status(400).json({ error: 'Name, category, and price are required' });
  }
  if (typeof price !== 'number' || price <= 0) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO menu_items (name, category, price, image, description) VALUES (?, ?, ?, ?, ?)',
      [name, category, price, image, description]
    );
    const [item] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image,
      rating: item.rating
    });
  } catch (error) {
    console.error('Error adding menu item:', error);
    res.status(500).json({ error: 'Failed to add menu item' });
  }
});

app.put('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, category, price, image, description } = req.body;
  if (!name || !category || !price) {
    return res.status(400).json({ error: 'Name, category, and price are required' });
  }
  if (typeof price !== 'number' || price <= 0) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  try {
    const [result] = await pool.query(
      'UPDATE menu_items SET name = ?, category = ?, price = ?, image = ?, description = ? WHERE id = ?',
      [name, category, price, image, description, id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Menu item not found' });
    const [item] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [id]);
    res.json({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image,
      rating: item.rating
    });
  } catch (error) {
    console.error('Error updating menu item:', error);
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

app.delete('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM menu_items WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    console.error('Error deleting menu item:', error);
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

app.post('/api/menu/:id/rate', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { rating, review } = req.body;
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be between 1 and 5' });
  }
  try {
    const [itemCheck] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [id]);
    if (!itemCheck[0]) return res.status(404).json({ error: 'Menu item not found' });
    await pool.query('UPDATE menu_items SET rating = ? WHERE id = ?', [rating, id]);
    res.json({ message: 'Rating submitted successfully' });
  } catch (error) {
    console.error('Error submitting rating:', error);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

app.get('/api/offers', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM offers ORDER BY created_at DESC');
    const offers = result.map(offer => ({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image,
      created_at: offer.created_at
    }));
    res.json(offers);
  } catch (error) {
    console.error('Error fetching offers:', error);
    res.status(500).json({ error: 'Failed to fetch offers' });
  }
});

app.get('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('SELECT * FROM offers WHERE id = ?', [id]);
    const offer = result[0];
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    res.json({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image
    });
  } catch (error) {
    console.error('Error fetching offer:', error);
    res.status(500).json({ error: 'Failed to fetch offer' });
  }
});

app.post('/api/offers', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, price, image, description } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'Name and price required' });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO offers (name, price, image, description) VALUES (?, ?, ?, ?)',
      [name, price, image, description]
    );
    const [offer] = await pool.query('SELECT * FROM offers WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image
    });
  } catch (error) {
    console.error('Error adding offer:', error);
    res.status(500).json({ error: 'Failed to add offer' });
  }
});

app.put('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, price, image, description } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'Name and price required' });
  }
  try {
    const [result] = await pool.query(
      'UPDATE offers SET name = ?, price = ?, image = ?, description = ? WHERE id = ?',
      [name, price, image, description, id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Offer not found' });
    const [offer] = await pool.query('SELECT * FROM offers WHERE id = ?', [id]);
    res.json({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image
    });
  } catch (error) {
    console.error('Error updating offer:', error);
    res.status(500).json({ error: 'Failed to update offer' });
  }
});

app.delete('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM offers WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Offer not found' });
    }
    res.json({ message: 'Offer deleted successfully' });
  } catch (error) {
    console.error('Error deleting offer:', error);
    res.status(500).json({ error: 'Failed to delete offer' });
  }
});

app.get('/api/coupons', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM coupons ORDER BY created_at DESC');
    const coupons = result.map(coupon => ({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image,
      created_at: coupon.created_at
    }));
    res.json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

app.get('/api/coupons/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('SELECT * FROM coupons WHERE id = ?', [id]);
    const coupon = result[0];
    if (!coupon) return res.status(404).json({ error: 'Coupon not found' });
    res.json({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image
    });
  } catch (error) {
    console.error('Error fetching coupon:', error);
    res.status(500).json({ error: 'Failed to fetch coupon' });
  }
});

app.post('/api/coupons', authenticateToken, authenticateAdmin, async (req, res) => {
  const { code, discount, image, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  if (typeof discount !== 'number' || discount < 1 || discount > 100) {
    return res.status(400).json({ error: 'Discount must be a number between 1 and 100' });
  }
  try {
    const [codeCheck] = await pool.query('SELECT * FROM coupons WHERE code = ?', [code]);
    if (codeCheck.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    const [result] = await pool.query(
      'INSERT INTO coupons (code, discount, image, description) VALUES (?, ?, ?, ?)',
      [code, discount, image, description]
    );
    const [coupon] = await pool.query('SELECT * FROM coupons WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image,
      created_at: coupon.created_at
    });
  } catch (error) {
    console.error('Error adding coupon:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    res.status(500).json({ error: 'Failed to add coupon' });
  }
});

app.put('/api/coupons/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { code, discount, image, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  if (typeof discount !== 'number' || discount < 1 || discount > 100) {
    return res.status(400).json({ error: 'Discount must be a number between 1 and 100' });
  }
  try {
    const [codeCheck] = await pool.query('SELECT * FROM coupons WHERE code = ? AND id != ?', [code, id]);
    if (codeCheck.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    const [result] = await pool.query(
      'UPDATE coupons SET code = ?, discount = ?, image = ?, description = ? WHERE id = ?',
      [code, discount, image, description, id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Coupon not found' });
    const [coupon] = await pool.query('SELECT * FROM coupons WHERE id = ?', [id]);
    res.json({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image
    });
  } catch (error) {
    console.error('Error updating coupon:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    res.status(500).json({ error: 'Failed to update coupon' });
  }
});

app.delete('/api/coupons/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM coupons WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    res.json({ message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('Error deleting coupon:', error);
    res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

app.post('/api/coupons/validate', authenticateToken, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }
  try {
    const [result] = await pool.query('SELECT * FROM coupons WHERE code = ?', [couponCode]);
    const coupon = result[0];
    if (!coupon) {
      return res.status(404).json({ error: 'Invalid coupon code' });
    }
    res.json({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image
    });
  } catch (error) {
    console.error('Error validating coupon:', error);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

app.get('/api/contact', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
    const messages = result.map(message => ({
      _id: message.id,
      name: message.name,
      email: message.email,
      subject: message.subject,
      message: message.message,
      status: message.status,
      created_at: message.created_at
    }));
    res.json(messages);
  } catch (error) {
    console.error('Error fetching contact messages:', error);
    res.status(500).json({ error: 'Failed to fetch contact messages' });
  }
});

app.get('/api/contact/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('SELECT * FROM contact_messages WHERE id = ?', [id]);
    const message = result[0];
    if (!message) return res.status(404).json({ error: 'Message not found' });
    res.json({
      _id: message.id,
      name: message.name,
      email: message.email,
      subject: message.subject,
      message: message.message,
      status: message.status,
      created_at: message.created_at
    });
  } catch (error) {
    console.error('Error fetching contact message:', error);
    res.status(500).json({ error: 'Failed to fetch message' });
  }
});

app.post('/api/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO contact_messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
      [name, email, subject, message]
    );
    const [newMessage] = await pool.query('SELECT * FROM contact_messages WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: newMessage.id,
      name: newMessage.name,
      email: newMessage.email,
      subject: newMessage.subject,
      message: newMessage.message,
      status: newMessage.status,
      created_at: newMessage.created_at
    });
  } catch (error) {
    console.error('Error adding contact message:', error);
    res.status(500).json({ error: 'Failed to add contact message' });
  }
});

app.post('/api/contact/:id/reply', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { subject, message: replyMessage } = req.body;

  if (!subject || !replyMessage) {
    return res.status(400).json({ error: 'Subject and reply message are required' });
  }

  try {
    const [messageResult] = await pool.query('SELECT name, email, subject AS original_subject FROM contact_messages WHERE id = ?', [id]);
    const contactMessage = messageResult[0];
    if (!contactMessage) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: contactMessage.email,
      subject: `Re: ${contactMessage.original_subject}`,
      text: replyMessage,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #f59e0b; font-size: 24px;">Delicute</h2>
          <p style="font-size: 16px;">Dear ${contactMessage.name},</p>
          <p style="font-size: 16px; line-height: 1.6;">Thank you for reaching out to us. Below is our response to your inquiry:</p>
          <p style="font-size: 16px; line-height: 1.6; background-color: #f9f9f9; padding: 15px; border-radius: 4px;">${replyMessage}</p>
          <p style="font-size: 16px;">If you have any further questions, feel free to contact us.</p>
          <p style="font-size: 16px;">Best regards,<br>Delicute Team</p>
          <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 20px 0;">
          <p style="font-size: 14px; color: #666;">Original Message:<br>${contactMessage.original_subject}</p>
        </div>
      `
    });

    await pool.query('UPDATE contact_messages SET status = ? WHERE id = ?', ['Replied', id]);

    res.json({ message: 'Reply sent successfully' });
  } catch (error) {
    console.error('Error sending reply:', error);
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

app.delete('/api/contact/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM contact_messages WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    console.error('Error deleting contact message:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.isAdmin;
    let query;
    let values = [];
    if (isAdmin) {
      query = `
        SELECT orders.*, users.email, users.name as customer_name, 
               addresses.full_name, addresses.house_number, addresses.street, addresses.landmark, addresses.pincode
        FROM orders 
        JOIN users ON orders.user_id = users.id 
        LEFT JOIN addresses ON orders.delivery_address_id = addresses.id
        ORDER BY orders.created_at DESC
      `;
    } else {
      query = `
        SELECT orders.*, 
               addresses.full_name, addresses.house_number, addresses.street, addresses.landmark, addresses.pincode
        FROM orders 
        LEFT JOIN addresses ON orders.delivery_address_id = addresses.id
        WHERE orders.user_id = ? 
        ORDER BY orders.created_at DESC
      `;
      values = [req.user.id];
    }
    const [result] = await pool.query(query, values);
    const orders = result.map(order => ({
      _id: order.id,
      customerName: order.customer_name || undefined,
      email: order.email || undefined,
      total: order.total,
      status: order.status,
      paymentStatus: order.payment_status,
      paymentMethod: order.payment_method,
      items: order.items,
      coupon: order.coupon,
      discount: order.discount,
      deliveryAddress: order.full_name ? {
        fullName: order.full_name,
        houseNumber: order.house_number,
        street: order.street,
        landmark: order.landmark,
        pincode: order.pincode
      } : null,
      created_at: order.created_at
    }));
    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT orders.*, 
             addresses.full_name, addresses.house_number, addresses.street, addresses.landmark, addresses.pincode
      FROM orders 
      LEFT JOIN addresses ON orders.delivery_address_id = addresses.id
      WHERE orders.id = ? AND orders.user_id = ?
    `;
    const [result] = await pool.query(query, [id, req.user.id]);
    const order = result[0];
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json({
      _id: order.id,
      total: order.total,
      status: order.status,
      paymentStatus: order.payment_status,
      paymentMethod: order.payment_method,
      items: order.items,
      coupon: order.coupon,
      discount: order.discount,
      deliveryAddress: order.full_name ? {
        fullName: order.full_name,
        houseNumber: order.house_number,
        street: order.street,
        landmark: order.landmark,
        pincode: order.pincode
      } : null,
      created_at: order.created_at
    });
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

app.get('/api/orders/history', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT orders.*, 
             addresses.full_name, addresses.house_number, addresses.street, addresses.landmark, addresses.pincode
      FROM orders 
      LEFT JOIN addresses ON orders.delivery_address_id = addresses.id
      WHERE orders.user_id = ? AND orders.status IN ('Delivered', 'Cancelled')
      ORDER BY orders.created_at DESC
    `;
    const [result] = await pool.query(query, [req.user.id]);
    const orders = result.map(order => ({
      _id: order.id,
      total: order.total,
      status: order.status,
      paymentStatus: order.payment_status,
      paymentMethod: order.payment_method,
      items: order.items.map(item => ({
        item: item.item,
        itemName: item.itemName,
        quantity: item.quantity,
        price: item.price
      })),
      coupon: order.coupon,
      discount: order.discount,
      deliveryAddress: order.full_name ? {
        fullName: order.full_name,
        houseNumber: order.house_number,
        street: order.street,
        landmark: order.landmark,
        pincode: order.pincode
      } : null,
      created_at: order.created_at
    }));
    res.json(orders);
  } catch (error) {
    console.error('Error fetching order history:', error);
    res.status(500).json({ error: 'Failed to fetch order history' });
  }
});

app.delete('/api/orders/history', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE user_id = ? AND status IN (?, ?)', [req.user.id, 'Delivered', 'Cancelled']);
    res.json({ message: 'Order history cleared successfully' });
  } catch (error) {
    console.error('Error clearing order history:', error);
    res.status(500).json({ error: 'Failed to clear order history' });
  }
});

app.put('/api/orders/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['Pending', 'Confirmed', 'Delivered', 'Cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const [result] = await pool.query(
      'UPDATE orders SET status = ? WHERE id = ?',
      [status, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const [order] = await pool.query('SELECT id, status FROM orders WHERE id = ?', [id]);
    res.json({
      _id: order.id,
      status: order.status
    });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

app.post('/api/orders/:id/refund', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query(
      'UPDATE orders SET status = ?, payment_status = ? WHERE id = ?',
      ['Cancelled', 'Refunded', id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json({ message: 'Order refunded successfully' });
  } catch (error) {
    console.error('Error processing refund:', error);
    res.status(500).json({ error: 'Failed to process refund' });
  }
});

app.get('/api/orders/:id/track', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ?', [id, req.user.id]);
    const order = result[0];
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json({ status: order.status });
  } catch (error) {
    console.error('Error tracking order:', error);
    res.status(500).json({ error: 'Failed to track order' });
  }
});

app.get('/api/users', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT id, name, email, phone, is_blocked FROM users WHERE is_admin = FALSE ORDER BY created_at DESC');
    const customers = result.map(user => ({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      status: user.is_blocked ? 'Blocked' : 'Active'
    }));
    res.json(customers);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [userResult] = await pool.query('SELECT id, name, email, phone, is_blocked FROM users WHERE id = ? AND is_admin = FALSE', [id]);
    const user = userResult[0];
    if (!user) return res.status(404).json({ error: 'Customer not found' });

    const [ordersResult] = await pool.query('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [id]);
    const orders = ordersResult.map(order => ({
      _id: order.id,
      total: order.total,
      status: order.status,
      createdAt: order.created_at
    }));

    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      status: user.is_blocked ? 'Blocked' : 'Active',
      orders
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.put('/api/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const isBlocked = status === 'Blocked';
  try {
    const [result] = await pool.query(
      'UPDATE users SET is_blocked = ? WHERE id = ? AND is_admin = FALSE',
      [isBlocked, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    const [user] = await pool.query('SELECT id, name, email, phone, is_blocked FROM users WHERE id = ?', [id]);
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      status: user.is_blocked ? 'Blocked' : 'Active'
    });
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

app.get('/api/restaurant/status', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT status FROM restaurant_status LIMIT 1');
    const status = result[0]?.status || 'Closed';
    res.json({ status });
  } catch (error) {
    console.error('Error fetching restaurant status:', error);
    res.status(500).json({ error: 'Failed to fetch restaurant status' });
  }
});

app.put('/api/restaurant/status', authenticateToken, authenticateAdmin, async (req, res) => {
  let { status } = req.body;
  status = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
  if (!['Open', 'Closed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const [result] = await pool.query(
      'UPDATE restaurant_status SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
      [status]
    );
    if (result.affectedRows === 0) {
      await pool.query(
        'INSERT INTO restaurant_status (id, status) VALUES (1, ?)',
        [status]
      );
    }
    res.json({ status });
  } catch (error) {
    console.error('Error updating restaurant status:', error);
    res.status(500).json({ error: 'Failed to update restaurant status' });
  }
});

app.post('/api/addresses', authenticateToken, async (req, res) => {
  const { fullName, mobile, houseNumber, street, landmark, pincode } = req.body;
  if (!fullName || !mobile || !houseNumber || !street || !pincode) {
    return res.status(400).json({ error: 'All fields except landmark are required' });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO addresses (user_id, full_name, mobile, house_number, street, landmark, pincode) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [req.user.id, fullName, mobile, houseNumber, street, landmark, pincode]
    );
    const [address] = await pool.query('SELECT * FROM addresses WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: address.id,
      fullName: address.full_name,
      mobile: address.mobile,
      houseNumber: address.house_number,
      street: address.street,
      landmark: address.landmark,
      pincode: address.pincode,
      created_at: address.created_at
    });
  } catch (error) {
    console.error('Error adding address:', error);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

app.get('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM addresses WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
    const addresses = result.map(address => ({
      _id: address.id,
      fullName: address.full_name,
      mobile: address.mobile,
      houseNumber: address.house_number,
      street: address.street,
      landmark: address.landmark,
      pincode: address.pincode,
      created_at: address.created_at
    }));
    res.json(addresses);
  } catch (error) {
    console.error('Error fetching addresses:', error);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

app.put('/api/addresses/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { fullName, mobile, houseNumber, street, landmark, pincode } = req.body;
  if (!fullName || !mobile || !houseNumber || !street || !pincode) {
    return res.status(400).json({ error: 'All fields except landmark are required' });
  }
  try {
    const [result] = await pool.query(
      'UPDATE addresses SET full_name = ?, mobile = ?, house_number = ?, street = ?, landmark = ?, pincode = ? WHERE id = ? AND user_id = ?',
      [fullName, mobile, houseNumber, street, landmark, pincode, id, req.user.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Address not found' });
    const [address] = await pool.query('SELECT * FROM addresses WHERE id = ?', [id]);
    res.json({
      _id: address.id,
      fullName: address.full_name,
      mobile: address.mobile,
      houseNumber: address.house_number,
      street: address.street,
      landmark: address.landmark,
      pincode: address.pincode,
      created_at: address.created_at
    });
  } catch (error) {
    console.error('Error updating address:', error);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

app.delete('/api/addresses/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM addresses WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Error deleting address:', error);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const [userCheck] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (userCheck.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, phone, password, is_admin) VALUES (?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, false]
    );
    const [user] = await pool.query('SELECT id, email, is_admin FROM users WHERE id = ?', [result.insertId]);
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to sign up' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = result[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/api/auth/admin/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const [userCheck] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (userCheck.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, phone, password, is_admin) VALUES (?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, true]
    );
    const [user] = await pool.query('SELECT id, email, is_admin FROM users WHERE id = ?', [result.insertId]);
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Admin signup error:', error);
    res.status(500).json({ error: 'Failed to sign up admin' });
  }
});

app.post('/api/auth/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND is_admin = ?', [email, true]);
    const user = result[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials or not an admin' });
    }
    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Failed to log in admin' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = result[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = ? WHERE email = ?', [otp, email]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: email,
      subject: 'Delicute - Password Reset OTP',
      text: `Your OTP: ${otp}`,
      html: `<p>Your OTP: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND reset_otp = ?', [email, otp]);
    const user = result[0];
    if (!user) return res.status(400).json({ error: 'Invalid OTP' });
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE users SET password = ?, reset_otp = NULL WHERE email = ?', [hashedPassword, email]);
      res.json({ message: 'Password reset successfully' });
    } else {
      res.json({ message: 'OTP verified successfully' });
    }
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.post('/api/auth/admin/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND is_admin = ?', [email, true]);
    const user = result[0];
    if (!user) return res.status(404).json({ error: 'Admin not found' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = ? WHERE email = ?', [otp, email]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: email,
      subject: 'Delicute - Admin Password Reset OTP',
      text: `Your OTP: ${otp}`,
      html: `<p>Your OTP: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending admin OTP:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/reset-password/admin', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND reset_otp = ? AND is_admin = ?', [email, otp, true]);
    const user = result[0];
    if (!user) return res.status(400).json({ error: 'Invalid OTP or not an admin' });
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE users SET password = ?, reset_otp = NULL WHERE email = ?', [hashedPassword, email]);
      res.json({ message: 'Password reset successfully' });
    } else {
      res.json({ message: 'OTP verified successfully' });
    }
  } catch (error) {
    console.error('Admin reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.get('/api/auth/google', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    scope: ['profile', 'email'],
    redirect_uri: `${CLIENT_URL}/api/auth/google/callback`
  });
  res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) {
    console.error('Google OAuth callback error:', error);
    return res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Google authentication failed')}`);
  }
  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();
    const { email, name } = data;

    let [result] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    let user = result[0];
    if (!user) {
      const [insertResult] = await pool.query(
        'INSERT INTO users (name, email, is_admin) VALUES (?, ?, ?)',
        [name || 'Google User', email, false]
      );
      [result] = await pool.query('SELECT id, email, is_admin FROM users WHERE id = ?', [insertResult.insertId]);
      user = result[0];
    }

    if (user.is_blocked) {
      return res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Account is blocked')}`);
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, isAdmin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.redirect(`${CLIENT_URL}/?token=${encodeURIComponent(token)}`);
  } catch (error) {
    console.error('Google OAuth error:', error);
    res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Google authentication error')}`);
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, total, paymentMethod, paymentDetails, deliveryAddressId, couponCode } = req.body;
  const userId = req.user.id;
  if (!items || !total || !paymentMethod || !deliveryAddressId) {
    return res.status(400).json({ error: 'Items, total, payment method, and delivery address are required' });
  }
  if (!['PayPal', 'GooglePay', 'PhonePe', 'COD'].includes(paymentMethod)) {
    return res.status(400).json({ error: 'Invalid payment method' });
  }
  try {
    const [restaurantStatus] = await pool.query('SELECT status FROM restaurant_status LIMIT 1');
    if (restaurantStatus[0]?.status === 'Closed') {
      return res.status(400).json({ error: 'Restaurant is currently closed' });
    }

    const [addressCheck] = await pool.query('SELECT * FROM addresses WHERE id = ? AND user_id = ?', [deliveryAddressId, userId]);
    if (!addressCheck[0]) {
      return res.status(400).json({ error: 'Invalid delivery address' });
    }

    let discount = 0;
    let coupon = null;
    if (couponCode) {
      const [couponResult] = await pool.query('SELECT * FROM coupons WHERE code = ?', [couponCode]);
      if (couponResult[0]) {
        coupon = couponResult[0].code;
        discount = Math.floor((total * couponResult[0].discount) / 100);
      } else {
        return res.status(400).json({ error: 'Invalid coupon code' });
      }
    }

    const finalTotal = total - discount;

    const [result] = await pool.query(
      'INSERT INTO orders (user_id, items, total, payment_method, payment_details, delivery_address_id, coupon, discount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, JSON.stringify(items), finalTotal, paymentMethod, JSON.stringify(paymentDetails || {}), deliveryAddressId, coupon, discount]
    );
    const orderId = result.insertId;

    if (paymentMethod === 'PayPal') {
      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer("return=representation");
      request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: 'INR',
            value: finalTotal.toFixed(2)
          }
        }],
        application_context: {
          return_url: `${CLIENT_URL}/payment/success`,
          cancel_url: `${CLIENT_URL}/payment/cancel`
        }
      });
      const order = await paypalClient.execute(request);
      await pool.query('UPDATE orders SET payment_details = ? WHERE id = ?', [
        JSON.stringify({ ...paymentDetails, paypalOrderId: order.result.id }),
        orderId
      ]);
      res.json({ orderId: order.result.id });
    } else if (paymentMethod === 'GooglePay') {
      // Mock Google Pay initiation (requires client-side integration)
      const paymentData = {
        paymentMethodData: {
          type: 'UPI',
          tokenizationData: {
            token: paymentDetails?.token || 'mock-google-pay-token'
          }
        },
        amount: finalTotal * 100,
        currency: 'INR',
        transactionId: `gpay_${orderId}`
      };
      await pool.query('UPDATE orders SET payment_details = ? WHERE id = ?', [
        JSON.stringify({ ...paymentDetails, googlePayTransactionId: paymentData.transactionId }),
        orderId
      ]);
      res.json({ orderId: paymentData.transactionId, amount: finalTotal * 100, currency: 'INR' });
    } else if (paymentMethod === 'PhonePe') {
      // Mock PhonePe initiation (requires client-side integration)
      const payload = {
        merchantId: PHONEPE_MERCHANT_ID,
        merchantTransactionId: `phonepe_${orderId}`,
        amount: finalTotal * 100,
        currency: 'INR',
        redirectUrl: `${CLIENT_URL}/payment/success`,
        redirectMode: 'REDIRECT',
        merchantUserId: userId.toString(),
      };
      const payloadString = JSON.stringify(payload);
      const checksum = crypto
        .createHmac('sha256', PHONEPE_SALT_KEY)
        .update(payloadString + '/pg/v1/pay' + PHONEPE_SALT_INDEX)
        .digest('hex');
      await pool.query('UPDATE orders SET payment_details = ? WHERE id = ?', [
        JSON.stringify({ ...paymentDetails, phonepeTransactionId: payload.merchantTransactionId, checksum }),
        orderId
      ]);
      res.json({ orderId: payload.merchantTransactionId, amount: finalTotal * 100, currency: 'INR', checksum });
    } else if (paymentMethod === 'COD') {
      await pool.query('UPDATE orders SET status = ?, payment_status = ? WHERE id = ?', ['Confirmed', 'Pending', orderId]);
      res.json({ orderId: `cod_${orderId}`, message: 'Order placed successfully with COD' });
    }
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

app.post('/api/payment/paypal-capture', authenticateToken, async (req, res) => {
  const { orderId } = req.body;
  if (!orderId) {
    return res.status(400).json({ error: 'Order ID is required' });
  }
  try {
    const request = new paypal.orders.OrdersCaptureRequest(orderId);
    request.requestBody({});
    const capture = await paypalClient.execute(request);
    if (capture.result.status === 'COMPLETED') {
      const [result] = await pool.query(
        'UPDATE orders SET status = ?, payment_status = ?, payment_details = ? WHERE JSON_EXTRACT(payment_details, "$.paypalOrderId") = ?',
        ['Confirmed', 'Paid', JSON.stringify({ paypalOrderId: orderId, captureId: capture.result.id }), orderId]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Order not found' });
      }
      res.json({ message: 'Payment captured successfully' });
    } else {
      res.status(400).json({ error: 'Payment capture failed' });
    }
  } catch (error) {
    console.error('PayPal capture error:', error);
    res.status(500).json({ error: 'Failed to capture payment' });
  }
});

app.post('/api/payment/googlepay-verify', authenticateToken, async (req, res) => {
  const { orderId, paymentToken } = req.body;
  if (!orderId || !paymentToken) {
    return res.status(400).json({ error: 'Order ID and payment token are required' });
  }
  try {
    // Mock Google Pay verification (replace with actual Google Pay API call)
    const isValid = paymentToken.startsWith('mock-google-pay-token'); // Placeholder for actual verification
    if (isValid) {
      await pool.query(
        'UPDATE orders SET status = ?, payment_status = ? WHERE JSON_EXTRACT(payment_details, "$.googlePayTransactionId") = ?',
        ['Confirmed', 'Paid', orderId]
      );
      res.json({ message: 'Google Pay payment verified successfully' });
    } else {
      res.status(400).json({ error: 'Google Pay payment verification failed' });
    }
  } catch (error) {
    console.error('Google Pay verification error:', error);
    res.status(500).json({ error: 'Failed to verify Google Pay payment' });
  }
});

app.post('/api/payment/phonepe-verify', authenticateToken, async (req, res) => {
  const { orderId, checksum } = req.body;
  if (!orderId || !checksum) {
    return res.status(400).json({ error: 'Order ID and checksum are required' });
  }
  try {
    // Mock PhonePe verification (replace with actual PhonePe API call)
    const [order] = await pool.query('SELECT payment_details FROM orders WHERE JSON_EXTRACT(payment_details, "$.phonepeTransactionId") = ?', [orderId]);
    if (!order[0]) return res.status(404).json({ error: 'Order not found' });
    const storedChecksum = JSON.parse(order[0].payment_details).checksum;
    if (storedChecksum === checksum) {
      await pool.query(
        'UPDATE orders SET status = ?, payment_status = ? WHERE JSON_EXTRACT(payment_details, "$.phonepeTransactionId") = ?',
        ['Confirmed', 'Paid', orderId]
      );
      res.json({ message: 'PhonePe payment verified successfully' });
    } else {
      res.status(400).json({ error: 'PhonePe payment verification failed' });
    }
  } catch (error) {
    console.error('PhonePe verification error:', error);
    res.status(500).json({ error: 'Failed to verify PhonePe payment' });
  }
});

app.use((err, req, res, next) => {
  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();