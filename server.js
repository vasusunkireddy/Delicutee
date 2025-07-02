const express = require('express');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const path = require('path');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Validate critical environment variables
const requiredEnvVars = [
  'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME',
  'EMAIL_USER', 'EMAIL_PASS', 'SENDGRID_API_KEY', 'SENDGRID_FROM_EMAIL',
  'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER',
  'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET',
  'GOOGLE_CLIENT_ID', 'JWT_SECRET', 'SESSION_SECRET', 'CLIENT_URL'
];
const missingEnvVars = requiredEnvVars.filter(key => !process.env[key]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing environment variables:', missingEnvVars.join(', '));
  process.exit(1);
}

const app = express();

// Ensure Uploads directory exists
const uploadsDir = path.join(__dirname, 'Uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("✅ 'Uploads' directory created");
}

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verify Nodemailer transporter
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Nodemailer verification error:', error);
    process.exit(1);
  } else {
    console.log('✅ Nodemailer transporter verified');
  }
});

// CORS config
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:8080', process.env.CLIENT_URL],
  credentials: true
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/Uploads', express.static(uploadsDir));

// Session store config
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000, // Check every 15 minutes
  expiration: 60 * 60 * 1000, // Sessions expire after 1 hour
  ssl: { rejectUnauthorized: false }
});

// Session middleware
app.use(session({
  key: 'session_cookie',
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 60 * 60 * 1000 // 1 hour
  }
}));

// Session validation middleware
app.use((req, res, next) => {
  if (req.session && req.session.user) {
    // Check if session is expired
    const now = Date.now();
    const sessionExpiry = req.session.cookie.expires;
    if (sessionExpiry && now > sessionExpiry.getTime()) {
      // Session has expired
      req.session.destroy((err) => {
        if (err) {
          console.error('❌ Session destroy error:', err);
          return res.status(500).json({ message: 'Server error during session cleanup' });
        }
        return res.status(401).json({ message: 'Session expired. Please log in again.' });
      });
    } else {
      // Extend session on activity
      req.session.touch();
      next();
    }
  } else {
    // No session or no user in session
    if (req.path.includes('/api/admin') || req.path.includes('/api/userdashboard')) {
      return res.status(401).json({ message: 'Session expired or not authenticated. Please log in.' });
    }
    next();
  }
});

// MySQL DB connection
async function initializeDatabase() {
  try {
    const db = await mysql.createPool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      ssl: { rejectUnauthorized: false },
      connectionLimit: 10,
      waitForConnections: true,
      queueLimit: 0
    });
    console.log('✅ Database connected');
    return db;
  } catch (error) {
    console.error('❌ Database connection error:', error);
    throw error;
  }
}

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Routes
const indexRoutes = require('./routes/index');
const userDashboardRoutes = require('./routes/userdashboard');
const adminDashboardRoutes = require('./routes/admindashboard');

app.use('/api', indexRoutes);
app.use('/api', userDashboardRoutes);
app.use('/api/admin', adminDashboardRoutes);

// Frontend HTML pages
app.get('/admin', (req, res) => {
  if (req.session.user) {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  } else {
    res.redirect('/login');
  }
});

app.get('/admindashboard', (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    res.sendFile(path.join(__dirname, 'public', 'admindashboard.html'));
  } else {
    res.status(403).json({ message: 'Access denied. Admin role required.' });
  }
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

// Start server
const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    const db = await initializeDatabase();
    app.set('db', db);
    app.set('transporter', transporter);
    app.set('googleClient', googleClient);
    console.log('✅ Server setup complete');
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT} at ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();