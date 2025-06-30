const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Database connection
async function getDbConnection() {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            port: process.env.DB_PORT || 3306,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
        });
        console.log('Database connected successfully');
        return connection;
    } catch (error) {
        console.error('Database connection error:', error);
        throw new Error('Database connection failed');
    }
}

// Generate OTP
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
        console.log(`Email sent to ${to}`);
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

// Restaurant status route
router.get('/restaurant-status', async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
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
        res.status(200).json({ message: `Restaurant is ${restaurantStatus.toLowerCase()}`, status: restaurantStatus.toLowerCase() });
    } catch (error) {
        console.error('Fetch restaurant status error:', error);
        res.status(500).json({ message: 'Server error.' });
    } finally {
        if (db) await db.end();
    }
});

// Fetch active orders
router.get('/active-orders', async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const ordersTableExists = await tableExists(db, 'orders');
        if (!ordersTableExists) {
            console.log('Orders table not found');
            return res.status(500).json({ message: 'Orders table not found. Please contact support.' });
        }
        const [orders] = await db.execute(
            'SELECT * FROM orders WHERE status IN (?, ?)',
            ['PENDING', 'PREPARING']
        );
        res.status(200).json(orders);
    } catch (error) {
        console.error('Fetch active orders error:', error);
        res.status(500).json({ message: 'Server error.' });
    } finally {
        if (db) await db.end();
    }
});

// Admin signup route
router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        console.log('Signup failed: Missing fields', { name, email, password: password ? '[provided]' : '[missing]' });
        return res.status(400).json({ message: 'All fields (name, email, password) are required.' });
    }

    let db;
    try {
        db = await getDbConnection();
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

        res.status(200).json({ message: 'Admin sign up successful. Please log in.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error.' });
    } finally {
        if (db) await db.end();
    }
});

// Admin login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        console.log('Login failed: Missing email or password', { email, password: password ? '[provided]' : '[missing]' });
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    let db;
    try {
        db = await getDbConnection();
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
        res.status(500).json({ message: 'Server error.' });
    } finally {
        if (db) await db.end();
    }
});

// Admin forgot password route
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        console.log('Forgot password failed: Email is required');
        return res.status(400).json({ message: 'Email is required.' });
    }

    let db;
    try {
        db = await getDbConnection();
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
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

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
        res.status(500).json({ message: 'Server error.' });
    } finally {
        if (db) await db.end();
    }
});

// Admin reset password route
router.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword, confirmPassword } = req.body;
    if (!email || !otp) {
        console.log('Reset password failed: Email and OTP are required', { email, otp });
        return res.status(400).json({ message: 'Email and OTP are required.' });
    }

    let db;
    try {
        db = await getDbConnection();
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

        if (newPassword && confirmPassword) {
            if (newPassword !== confirmPassword) {
                console.log('Reset password failed: Passwords do not match', { email });
                return res.status(400).json({ message: 'Passwords do not match.' });
            }
            if (newPassword.length < 6) {
                console.log('Reset password failed: Password too short', { email });
                return res.status(400).json({ message: 'Password must be at least 6 characters.' });
            }
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await db.execute(
                'UPDATE users SET password = ?, otp = NULL, otp_expires = NULL WHERE email = ?',
                [hashedPassword, email]
            );
            console.log('Password reset successfully:', { email });
            res.status(200).json({ message: 'Admin password reset successfully.' });
        } else {
            console.log('OTP verified successfully:', { email, otp });
            res.status(200).json({ message: 'OTP verified successfully.' });
        }
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error.' });
    } finally {
        if (db) await db.end();
    }
});

// Admin logout route
router.post('/logout', (req, res) => {
    console.log('Logout successful');
    res.status(200).json({ message: 'Logged out successfully.' });
});

module.exports = router;