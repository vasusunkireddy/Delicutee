const jwt = require('jsonwebtoken');
const pool = require('../config/db');

const verifyToken = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (result.rows.length === 0) return res.status(401).json({ message: 'Invalid token' });
    req.user = result.rows[0];
    next();
  } catch (err) {
    res.status(401).json({ message: 'Unauthorized' });
  }
};

const isAdmin = async (req, res, next) => {
  if (!req.user.is_admin) return res.status(403).json({ message: 'Admin access required' });
  next();
};

module.exports = { verifyToken, isAdmin };