const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// Nodemailer transporter (reusing from server.js)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const db = req.app.get('db');
        const [rows] = await db.execute('SELECT * FROM admins WHERE email = ?', [email]);
        const admin = rows[0];
        if (!admin) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        const token = jwt.sign({ id: admin.id, email: admin.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Signup
router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const db = req.app.get('db');
        const [existing] = await db.execute('SELECT * FROM admins WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute('INSERT INTO admins (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);
        res.json({ message: 'Signup successful. Please login.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Forgot Password
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const db = req.app.get('db');
        const [rows] = await db.execute('SELECT * FROM admins WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Email not found' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await db.execute('UPDATE admins SET reset_otp = ?, otp_expiry = ? WHERE email = ?', [
            otp,
            new Date(Date.now() + 10 * 60 * 1000), // OTP expires in 10 minutes
            email
        ]);
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Delicute Password Reset OTP',
            text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`
        });
        res.json({ message: 'OTP sent to your email' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const db = req.app.get('db');
        const [rows] = await db.execute('SELECT * FROM admins WHERE email = ? AND reset_otp = ? AND otp_expiry > ?', [
            email,
            otp,
            new Date()
        ]);
        if (rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }
        res.json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword, confirmPassword } = req.body;
    try {
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }
        const db = req.app.get('db');
        const [rows] = await db.execute('SELECT * FROM admins WHERE email = ? AND reset_otp = ? AND otp_expiry > ?', [
            email,
            otp,
            new Date()
        ]);
        if (rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE admins SET password = ?, reset_otp = NULL, otp_expiry = NULL WHERE email = ?', [
            hashedPassword,
            email
        ]);
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Restaurant Status (sample implementation)
router.get('/restaurant-status', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        jwt.verify(token, process.env.JWT_SECRET);
        const hour = new Date().getHours();
        const isOpen = (hour >= 16 || hour < 0) || (hour >= 12); // Open 4PM-12AM Mon-Fri, 12PM-12AM Sat-Sun
        res.json({ message: `Restaurant is ${isOpen ? 'open' : 'closed'}`, status: isOpen ? 'open' : 'closed' });
    } catch (error) {
        console.error('Restaurant status error:', error);
        res.status(401).json({ message: 'Invalid token' });
    }
});

// Verify Token
router.get('/verify-token', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }
        jwt.verify(token, process.env.JWT_SECRET);
        res.json({ success: true, message: 'Token valid' });
    } catch (error) {
        console.error('Verify token error:', error);
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
});

module.exports = router;