const express = require('express');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const path = require('path');

// Load environment variables from .env
dotenv.config();

const app = express();

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// CORS configuration
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:8080'], // Allow frontend origins
    credentials: true
}));

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));

// Session configuration
const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    clearExpired: true,
    checkExpirationInterval: 15 * 60 * 1000,
    expiration: 60 * 60 * 1000,
    ssl: {
        rejectUnauthorized: false
    }
});

app.use(session({
    key: 'session_cookie',
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 60 * 60 * 1000
    }
}));

// MySQL Database Connection
async function initializeDatabase() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        ssl: {
            rejectUnauthorized: false
        }
    });
    return db;
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

// Serve static frontend pages
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admindashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admindashboard.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err.stack);
    res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

// Start the server
const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        const db = await initializeDatabase();
        console.log('Database connected successfully');
        app.set('db', db); // Make db available to routes
        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT} at ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();