const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');
const router = express.Router();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Google OAuth
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  res.redirect(`${process.env.CLIENT_URL}?token=${req.user.token}`);
});

// Signup
router.post('/signup', async (req, res) => {
  const { full_name, email, phone, password, address } = req.body;
  if (full_name.length < 3 || !/^\d{10}$/.test(phone) || password.length < 8 || !address) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (full_name, email, phone, password, address) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [full_name, email, phone, hashedPassword, address]
    );
    const token = jwt.sign({ id: result.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (err) {
    res.status(400).json({ message: 'Email already exists' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0 || !(await bcrypt.compare(password, result.rows[0].password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: result.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Forgot Password - Send OTP
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  try {
    await pool.query('UPDATE users SET reset_otp = $1, otp_expiry = NOW() + INTERVAL \'5 minutes\' WHERE email = $2', [otp, email]);
    await transporter.sendMail({
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP is ${otp}. It is valid for 5 minutes.`
    });
    res.json({ message: 'OTP sent' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  const { email, otp, new_password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND reset_otp = $2 AND otp_expiry > NOW()',
      [email, otp]
    );
    if (result.rows.length === 0) return res.status(400).json({ message: 'Invalid or expired OTP' });
    const hashedPassword = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password = $1, reset_otp = NULL, otp_expiry = NULL WHERE email = $2', [hashedPassword, email]);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Menu
router.get('/menu', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu_items');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Create Order
router.post('/order', async (req, res) => {
  const { items, total } = req.body;
  try {
    const order = await razorpay.orders.create({ amount: total * 100, currency: 'INR' });
    await pool.query('INSERT INTO orders (user_id, items, total, razorpay_order_id) VALUES ($1, $2, $3, $4) RETURNING *', [
      req.user?.id || null,
      JSON.stringify(items),
      total,
      order.id
    ]);
    res.json({ orderId: order.id, key: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;