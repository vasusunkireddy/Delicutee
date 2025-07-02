const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    pool: true,
    maxConnections: 5,
    rateLimit: 10,
});

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10,
    waitForConnections: true,
    queueLimit: 0,
});

// Utility Functions
// Generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send professional email
async function sendEmail(to, subject, html) {
    const mailOptions = {
        from: `Delicute <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html,
    };
    try {
        await transporter.sendMail(mailOptions);
        console.log(`Email sent successfully to ${to}`);
        return true;
    } catch (error) {
        console.error('Email sending error:', error);
        return false;
    }
}

// Check if table exists
async function tableExists(db, tableName) {
    try {
        await db.execute(`SELECT 1 FROM \`${tableName}\` LIMIT 1`);
        console.log(`Table ${tableName} exists`);
        return true;
    } catch (error) {
        if (error.code === 'ER_NO_SUCH_TABLE') {
            console.log(`Table ${tableName} does not exist`);
            return false;
        }
        throw error;
    }
}

// Check if column exists
async function columnExists(db, tableName, columnName) {
    try {
        const safeColumnName = columnName.replace(/[^a-zA-Z0-9_]/g, '');
        const [columns] = await db.execute(
            `SHOW COLUMNS FROM \`${tableName}\` LIKE ?`,
            [safeColumnName]
        );
        const exists = columns.length > 0;
        console.log(`Column ${columnName} in ${tableName}: ${exists ? 'exists' : 'does not exist'}`);
        return exists;
    } catch (error) {
        console.error(`Error checking column ${columnName} in ${tableName}:`, error);
        return false;
    }
}

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        console.log('Authentication failed: No token provided');
        return res.status(401).json({ message: 'Authentication required.' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Token verification failed:', error);
        return res.status(403).json({ message: 'Invalid or expired token.' });
    }
}

// Routes
// Restaurant status route
router.get('/restaurant-status', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await pool.getConnection();
        let restaurantStatus = 'Closed';
        const settingsTableExists = await tableExists(db, 'settings');
        if (settingsTableExists) {
            const hasKeyColumn = await columnExists(db, 'settings', 'key');
            if (hasKeyColumn) {
                const [settings] = await db.execute(
                    'SELECT value FROM settings WHERE `key` = ?',
                    ['restaurant_status']
                );
                restaurantStatus = settings[0]?.value || 'Closed';
            } else {
                console.warn('Settings table exists but key column not found');
            }
        } else {
            console.warn('Settings table not found');
        }
        res.status(200).json({
            message: `Restaurant is ${restaurantStatus.toLowerCase()}`,
            status: restaurantStatus.toLowerCase(),
        });
    } catch (error) {
        console.error('Fetch restaurant status error:', error);
        res.status(500).json({ message: 'Server error while fetching restaurant status.' });
    } finally {
        if (db) db.release();
    }
});

// Admin signup route
router.post('/signup', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    // Input validation
    if (!name || !email || !password || !confirmPassword) {
        console.log('Signup failed: Missing fields', { name, email, password: password ? '[provided]' : '[missing]', confirmPassword: confirmPassword ? '[provided]' : '[missing]' });
        return res.status(400).json({ message: 'All fields (name, email, password, confirmPassword) are required.' });
    }

    if (!/^[a-zA-Z\s]{2,}$/.test(name)) {
        console.log('Signup failed: Invalid name', { name });
        return res.status(400).json({ message: 'Name must be at least 2 characters and contain only letters and spaces.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        console.log('Signup failed: Invalid email', { email });
        return res.status(400).json({ message: 'Invalid email format.' });
    }

    if (password !== confirmPassword) {
        console.log('Signup failed: Passwords do not match', { email });
        return res.status(400).json({ message: 'Passwords do not match.' });
    }

    if (password.length < 6) {
        console.log('Signup failed: Password too short', { email });
        return res.status(400).json({ message: 'Password must be at least 6 characters.' });
    }

    let db;
    try {
        db = await pool.getConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            console.log('Users table not found');
            return res.status(500).json({ message: 'Users table not found. Please contact support.' });
        }

        const [existingEmail] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existingEmail.length > 0) {
            console.log('Signup failed: Email already registered', { email });
            return res.status(400).json({ message: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO users (name, email, password, is_verified, role) VALUES (?, ?, ?, ?, ?)',
            [name, email, hashedPassword, 1, 'admin']
        );
        console.log('User signed up successfully:', { name, email });

        const html = `
            <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                <h2 style="color: #1a202c; font-family: 'Playfair Display', serif;">Welcome to Delicute Admin Portal!</h2>
                <p style="color: #4a5568;">Dear ${name},</p>
                <p style="color: #4a5568;">Congratulations! Your Delicute admin account has been successfully created. You can now manage our culinary operations.</p>
                <p style="color: #4a5568;">Log in to the admin portal to start managing orders, menus, and more.</p>
                <a href="${process.env.CLIENT_URL}/admin.html" style="display: inline-block; background-color: #d69e2e; color: #ffffff; padding: 10px 20px; border-radius: 5px; text-decoration: none; margin: 20px 0;">Log In Now</a>
                <p style="color: #4a5568;">If you have any questions, contact us at <a href="mailto:contactdelicute@gmail.com" style="color: #d69e2e;">contactdelicute@gmail.com</a>.</p>
                <p style="color: #4a5568; margin-top: 20px;">Best regards,<br>The Delicute Team</p>
                <p style="color: #718096; font-size: 12px; text-align: center;">© 2025 Delicute. All rights reserved.</p>
            </div>
        `;

        const sent = await sendEmail(email, 'Delicute - Welcome to Admin Portal!', html);
        if (!sent) {
            console.log('Signup successful, but email sending failed:', { email });
            return res.status(500).json({ message: 'Account created, but failed to send welcome email.' });
        }

        res.status(200).json({ message: 'Admin signup successful. Please log in.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during signup.' });
    } finally {
        if (db) db.release();
    }
});

// Admin login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
        console.log('Login failed: Missing email or password', { email, password: password ? '[provided]' : '[missing]' });
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        console.log('Login failed: Invalid email', { email });
        return res.status(400).json({ message: 'Invalid email format.' });
    }

    let db;
    try {
        db = await pool.getConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            console.log('Users table not found');
            return res.status(500).json({ message: 'Users table not found. Please contact support.' });
        }

        const [users] = await db.execute(
            'SELECT * FROM users WHERE email = ? AND role = ? AND is_verified = ?',
            [email, 'admin', 1]
        );
        if (users.length === 0) {
            console.log('Login failed: Admin not found or not verified', { email });
            return res.status(400).json({ message: 'Admin not found or not verified.' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login failed: Invalid password', { email });
            return res.status(400).json({ message: 'Invalid password.' });
        }

        const token = jwt.sign({ id: user.id, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
        console.log('Login successful:', { email });
        res.status(200).json({ message: 'Admin login successful.', token, redirect: '/admindashboard.html' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    } finally {
        if (db) db.release();
    }
});

// Admin forgot password route
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    // Input validation
    if (!email) {
        console.log('Forgot password failed: Email is required', { email });
        return res.status(400).json({ message: 'Email is required.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        console.log('Forgot password failed: Invalid email', { email });
        return res.status(400).json({ message: 'Invalid email format.' });
    }

    let db;
    try {
        db = await pool.getConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            console.log('Users table not found');
            return res.status(500).json({ message: 'Users table not found. Please contact support.' });
        }

        const [users] = await db.execute(
            'SELECT * FROM users WHERE email = ? AND role = ?',
            [email, 'admin']
        );
        if (users.length === 0) {
            console.log('Forgot password failed: Admin email not registered', { email });
            return res.status(400).json({ message: 'Admin email not registered.' });
        }

        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry

        await db.execute(
            'UPDATE users SET otp = ?, otp_expires = ? WHERE email = ?',
            [otp, otpExpires, email]
        );
        console.log('OTP generated and saved:', { email, otp, otpExpires });

        const html = `
            <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                <h2 style="color: #1a202c; font-family: 'Playfair Display', serif;">Delicute - Admin Password Reset Request</h2>
                <p style="color: #4a5568;">Dear ${users[0].name},</p>
                <p style="color: #4a5568;">We received a request to reset your admin password. Please use the following One-Time Password (OTP) to proceed:</p>
                <h3 style="color: #d69e2e; font-size: 24px; text-align: center; margin: 20px 0;">${otp}</h3>
                <p style="color: #4a5568;">This OTP is valid for 10 minutes. Please enter it on the password reset page to set a new password.</p>
                <p style="color: #4a5568;">If you did not initiate this request, please contact our support team at <a href="mailto:contactdelicute@gmail.com" style="color: #d69e2e;">contactdelicute@gmail.com</a>.</p>
                <p style="color: #4a5568; margin-top: 20px;">Best regards,<br>The Delicute Team</p>
                <p style="color: #718096; font-size: 12px; text-align: center;">© 2025 Delicute. All rights reserved.</p>
            </div>
        `;

        const sent = await sendEmail(email, 'Delicute - Reset Your Admin Password', html);
        if (!sent) {
            console.log('Forgot password: Failed to send OTP email', { email });
            return res.status(500).json({ message: 'Failed to send OTP email. Please try again.' });
        }

        res.status(200).json({ message: 'OTP sent to your email.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error during forgot password process.' });
    } finally {
        if (db) db.release();
    }
});

// Admin verify OTP route
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    // Input validation
    if (!email || !otp) {
        console.log('Verify OTP failed: Email and OTP are required', { email, otp });
        return res.status(400).json({ message: 'Email and OTP are required.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        console.log('Verify OTP failed: Invalid email', { email });
        return res.status(400).json({ message: 'Invalid email format.' });
    }

    if (!/^\d{6}$/.test(otp)) {
        console.log('Verify OTP failed: Invalid OTP format', { email, otp });
        return res.status(400).json({ message: 'OTP must be a 6-digit number.' });
    }

    let db;
    try {
        db = await pool.getConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            console.log('Users table not found');
            return res.status(500).json({ message: 'Users table not found. Please contact support.' });
        }

        const [users] = await db.execute(
            'SELECT * FROM users WHERE email = ? AND role = ? AND otp = ? AND otp_expires > NOW()',
            [email, 'admin', otp]
        );
        if (users.length === 0) {
            console.log('Verify OTP failed: Invalid or expired OTP', { email, otp });
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        console.log('OTP verified successfully:', { email, otp });
        res.status(200).json({ message: 'OTP verified successfully.' });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ message: 'Server error during OTP verification.' });
    } finally {
        if (db) db.release();
    }
});

// Admin reset password route
router.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    // Input validation
    if (!email || !otp || !newPassword) {
        console.log('Reset password failed: Missing fields', { email, otp, newPassword: newPassword ? '[provided]' : '[missing]' });
        return res.status(400).json({ message: 'Email, OTP, and new password are required.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        console.log('Reset password failed: Invalid email', { email });
        return res.status(400).json({ message: 'Invalid email format.' });
    }

    if (!/^\d{6}$/.test(otp)) {
        console.log('Reset password failed: Invalid OTP format', { email, otp });
        return res.status(400).json({ message: 'OTP must be a 6-digit number.' });
    }

    if (newPassword.length < 6) {
        console.log('Reset password failed: Password too short', { email });
        return res.status(400).json({ message: 'New password must be at least 6 characters.' });
    }

    let db;
    try {
        db = await pool.getConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            console.log('Users table not found');
            return res.status(500).json({ message: 'Users table not found. Please contact support.' });
        }

        const [users] = await db.execute(
            'SELECT * FROM users WHERE email = ? AND role = ? AND otp = ? AND otp_expires > NOW()',
            [email, 'admin', otp]
        );
        if (users.length === 0) {
            console.log('Reset password failed: Invalid or expired OTP', { email, otp });
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute(
            'UPDATE users SET password = ?, otp = NULL, otp_expires = NULL WHERE email = ?',
            [hashedPassword, email]
        );
        console.log('Password reset successfully:', { email });

        res.status(200).json({ message: 'Admin password reset successfully.' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error during password reset.' });
    } finally {
        if (db) db.release();
    }
});

// Token verification route
router.get('/verify-token', authenticateToken, (req, res) => {
    console.log('Token verified successfully:', { userId: req.user.id });
    res.status(200).json({ success: true, message: 'Token is valid.' });
});

// Admin logout route
router.post('/logout', (req, res) => {
    console.log('Logout successful');
    res.status(200).json({ message: 'Logged out successfully.' });
});

module.exports = router;