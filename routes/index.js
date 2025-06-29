const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const dotenv = require('dotenv');

dotenv.config();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Database connection
async function getDbConnection() {
  return await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  });
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
    html
  };
  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
}

// Middleware to protect routes
function authenticateToken(req, res, next) {
  const token = req.session.user?.token || req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Authentication required.' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired token.' });
  }
}

// Serve login page (index.html)
router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

// Serve user dashboard (protected)
router.get('/userdashboard.html', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'userdashboard.html'));
});

// Serve admin dashboard (protected)
router.get('/admindashboard.html', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admins only.' });
  }
  res.sendFile(path.join(__dirname, '../public', 'admindashboard.html'));
});

// Signup route (no OTP required)
router.post('/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const db = await getDbConnection();
    const [existingEmail] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    const [existingPhone] = await db.execute('SELECT * FROM users WHERE phone = ?', [phone]);

    if (existingEmail.length > 0) {
      await db.end();
      return res.status(400).json({ message: 'Email already registered.' });
    }
    if (existingPhone.length > 0) {
      await db.end();
      return res.status(400).json({ message: 'Phone number already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute(
      'INSERT INTO users (name, email, phone, password, is_verified, role) VALUES (?, ?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, 1, 'user']
    );

    const html = `
      <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
        <h2 style="color: #1a202c; font-family: 'Playfair Display', serif;">Welcome to Delicute!</h2>
        <p style="color: #4a5568;">Dear ${name},</p>
        <p style="color: #4a5568;">Congratulations! Your Delicute account has been successfully created. You're now part of our culinary family, where every bite tells a story.</p>
        <p style="color: #4a5568;">Start exploring our delicious offerings and place your first order today!</p>
        <a href="${process.env.CLIENT_URL}/login" style="display: inline-block; background-color: #d69e2e; color: #ffffff; padding: 10px 20px; border-radius: 5px; text-decoration: none; margin: 20px 0;">Log In Now</a>
        <p style="color: #4a5568;">If you have any questions, contact us at <a href="mailto:contactdelicute@gmail.com" style="color: #d69e2e;">contactdelicute@gmail.com</a>.</p>
        <p style="color: #4a5568; margin-top: 20px;">Best regards,<br>The Delicute Team</p>
        <p style="color: #718096; font-size: 12px; text-align: center;">© 2025 Delicute. All rights reserved.</p>
      </div>
    `;

    const sent = await sendEmail(email, 'Delicute - Welcome to Our Family!', html);
    await db.end();
    if (!sent) {
      return res.status(500).json({ message: 'Account created, but failed to send welcome email.' });
    }

    res.status(200).json({ message: 'Sign up successful. Please log in.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  const { input, password } = req.body;
  if (!input || !password) {
    return res.status(400).json({ message: 'Email/phone and password are required.' });
  }

  try {
    const db = await getDbConnection();
    const [users] = await db.execute('SELECT * FROM users WHERE email = ? OR phone = ?', [input, input]);

    if (users.length === 0) {
      await db.end();
      return res.status(400).json({ message: 'User not found.' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await db.end();
      return res.status(400).json({ message: 'Invalid password.' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    req.session.user = { id: user.id, role: user.role, token }; // Store token in session
    await db.end();
    res.status(200).json({ message: 'Login successful.', token, redirect: user.role === 'admin' ? '/admindashboard.html' : '/userdashboard.html' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Forgot password route
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  try {
    const db = await getDbConnection();
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      await db.end();
      return res.status(400).json({ message: 'Email not registered.' });
    }

    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await db.execute('UPDATE users SET otp = ?, otp_expires = ? WHERE email = ?', [otp, otpExpires, email]);

    const html = `
      <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
        <h2 style="color: #1a202c; font-family: 'Playfair Display', serif;">Delicute - Password Reset Request</h2>
        <p style="color: #4a5568;">Dear ${users[0].name},</p>
        <p style="color: #4a5568;">We received a request to reset your password. Please use the following One-Time Password (OTP) to proceed:</p>
        <h3 style="color: #d69e2e; font-size: 24px; text-align: center; margin: 20px 0;">${otp}</h3>
        <p style="color: #4a5568;">This OTP is valid for 10 minutes. Please enter it on the password reset page to set a new password.</p>
        <p style="color: #4a5568;">If you did not initiate this request, please contact our support team at <a href="mailto:contactdelicute@gmail.com" style="color: #d69e2e;">contactdelicute@gmail.com</a>.</p>
        <p style="color: #4a5568; margin-top: 20px;">Best regards,<br>The Delicute Team</p>
        <p style="color: #718096; font-size: 12px; text-align: center;">© 2025 Delicute. All rights reserved.</p>
      </div>
    `;

    const sent = await sendEmail(email, 'Delicute - Reset Your Password', html);
    if (!sent) {
      await db.end();
      return res.status(500).json({ message: 'Failed to send OTP email. Please try again.' });
    }

    await db.end();
    res.status(200).json({ message: 'OTP sent to your email.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Verify OTP and reset password
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword, confirmPassword } = req.body;
  if (!email || !otp || !newPassword || !confirmPassword) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match.' });
  }

  try {
    const db = await getDbConnection();
    const [users] = await db.execute('SELECT * FROM users WHERE email = ? AND otp = ? AND otp_expires > NOW()', [email, otp]);

    if (users.length === 0) {
      await db.end();
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.execute('UPDATE users SET password = ?, otp = NULL, otp_expires = NULL WHERE email = ?', [hashedPassword, email]);
    await db.end();
    res.status(200).json({ message: 'Password reset successfully.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Google login route
router.post('/google-login', async (req, res) => {
  const { token } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const { email, name, sub: googleId } = ticket.getPayload();

    const db = await getDbConnection();
    let [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      await db.execute(
        'INSERT INTO users (name, email, google_id, is_verified, role) VALUES (?, ?, ?, ?, ?)',
        [name, email, googleId, 1, 'user']
      );
      [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    }

    const user = users[0];
    const jwtToken = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    req.session.user = { id: user.id, role: user.role, token: jwtToken };
    await db.end();
    res.status(200).json({ message: 'Google login successful.', token: jwtToken, redirect: '/userdashboard.html' });
  } catch (error) {
    console.error(error);
    res.status(400).json({ message: 'Google login failed.' });
  }
});

// Restaurant status route
router.get('/restaurant-status', (req, res) => {
  const now = new Date();
  const day = now.getDay();
  const hour = now.getHours();
  const isOpen = (day >= 1 && day <= 5 && hour >= 16 && hour < 24) || (day === 0 || day === 6 && hour >= 12 && hour < 24);
  res.status(200).json({
    status: isOpen ? 'open' : 'closed',
    message: isOpen ? 'Delicute is Open Now, Enjoy Your Day!' : 'Delicute is Closed Now, Sorry for the Inconvenience'
  });
});

module.exports = router;