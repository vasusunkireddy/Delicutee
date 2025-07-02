const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const winston = require('winston');

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'delicute',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000
});

// Retry logic for database operations
const withRetry = async (fn, retries = 3, delay = 1000) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      logger.error(`Database operation failed (attempt ${attempt}/${retries}): ${error.message}`, {
        code: error.code,
        errno: error.errno,
        sqlMessage: error.sqlMessage
      });
      if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
        if (attempt === retries) throw new Error(`Database connection failed after ${retries} attempts: ${error.message}`);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        throw error;
      }
    }
  }
};

// JWT authentication middleware
const authenticateToken = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    logger.warn('Unauthorized access attempt: No token provided', { path: req.path });
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  try {
    // Check if token is blacklisted
    const [blacklistRows] = await withRetry(async () => {
      return await pool.execute('SELECT token FROM blacklisted_tokens WHERE token = ?', [token]);
    });
    if (blacklistRows.length) {
      logger.warn('Unauthorized access attempt: Token blacklisted', { path: req.path });
      return res.status(401).json({ message: 'Unauthorized: Token invalid' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    if (!decoded.id || !decoded.role) {
      logger.error('Invalid token: Missing user_id or role', { path: req.path });
      return res.status(403).json({ message: 'Invalid token: Missing user_id or role' });
    }

    // Prevent admin access to customer routes
    if (decoded.role === 'admin' && req.path !== '/admin') {
      logger.warn('Unauthorized access attempt: Admin token used for customer route', { user_id: decoded.id, path: req.path });
      return res.status(403).json({ message: 'Unauthorized: Admin access not allowed' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    logger.error('Token verification error', { error: error.message, path: req.path });
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Multer configuration for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'Uploads/'),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|webp|gif|bmp|tiff/;
    const isValid = filetypes.test(path.extname(file.originalname).toLowerCase()) && filetypes.test(file.mimetype);
    if (isValid) return cb(null, true);
    cb(new Error('Images only (jpeg, jpg, png, webp, gif, bmp, tiff)'));
  },
  limits: { fileSize: 20 * 1024 * 1024 }
});

// Multer error handling middleware
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    logger.error(`File size error: ${err.message}`, {
      file: req.file?.originalname || 'unknown',
      size: req.file?.size || 'unknown',
      user_id: req.user?.id
    });
    return res.status(400).json({ message: 'File too large. Maximum size allowed is 20MB.' });
  }
  if (err) {
    logger.error(`Multer error: ${err.message}`, { user_id: req.user?.id });
    return res.status(400).json({ message: err.message });
  }
  next(err);
};

// Input sanitization utility
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input.replace(/[<>"'&]/g, '');
  }
  return input;
};

// Set no-cache headers for all responses
const setNoCacheHeaders = (res) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'Surrogate-Control': 'no-store'
  });
};

// Get user data
router.get('/user', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, email, phone, profileImage, googleUser, role FROM users WHERE id = ? AND role = ?',
        [req.user.id, 'user']
      );
    });
    if (!rows.length) {
      logger.warn(`User not found or not a customer: ${req.user.id}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'User not found or unauthorized role' });
    }
    logger.info(`Fetched user data for ID: ${req.user.id}`, { user_id: req.user.id });
    res.json({ user: rows[0] });
  } catch (error) {
    logger.error('Fetch user error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch user data' });
  }
});

// Get total orders count
router.get('/orders/count', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [rows] = await withRetry(async () => {
      return await pool.execute('SELECT COUNT(*) as count FROM orders WHERE user_id = ?', [req.user.id]);
    });
    logger.info(`Fetched order count for user: ${req.user.id}`, { count: rows[0].count, user_id: req.user.id });
    res.json({ count: rows[0].count });
  } catch (error) {
    logger.error('Fetch orders count error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch orders count' });
  }
});

// Get coupons
router.get('/coupons', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, code, description, image, discount FROM coupons WHERE active = 1 AND (user_id IS NULL OR user_id = ?)',
        [req.user.id]
      );
    });
    logger.info(`Fetched coupons for user: ${req.user.id}`, { count: rows.length, user_id: req.user.id });
    res.json({ coupons: rows });
  } catch (error) {
    logger.error('Fetch coupons error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch coupons' });
  }
});

// Get menu items
router.get('/menu', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, price, category, image, description FROM menu_items WHERE active = 1'
      );
    });
    logger.info(`Fetched menu items for user: ${req.user.id}`, { count: rows.length, user_id: req.user.id });
    res.json({ items: rows });
  } catch (error) {
    logger.error('Fetch menu error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch menu' });
  }
});

// Add item to cart
router.post('/cart/add', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) {
    logger.warn('Add to cart failed: Item ID missing', { user_id: req.user.id });
    return res.status(400).json({ message: 'Item ID is required' });
  }

  try {
    const sanitizedItemId = sanitizeInput(itemId);
    const [itemRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, price, image FROM menu_items WHERE id = ? AND active = 1',
        [sanitizedItemId]
      );
    });

    if (!itemRows.length) {
      logger.warn(`Item not found: ${sanitizedItemId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Item not found' });
    }

    const [cartRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, quantity FROM cart WHERE user_id = ? AND itemId = ?',
        [req.user.id, sanitizedItemId]
      );
    });

    if (cartRows.length) {
      await withRetry(async () => {
        await pool.execute('UPDATE cart SET quantity = quantity + 1 WHERE id = ?', [cartRows[0].id]);
      });
    } else {
      await withRetry(async () => {
        await pool.execute(
          'INSERT INTO cart (user_id, itemId, quantity) VALUES (?, ?, 1)',
          [req.user.id, sanitizedItemId]
        );
      });
    }

    logger.info(`Item added to cart: ${sanitizedItemId}`, { user_id: req.user.id });
    const updatedCart = await getCart(req.user.id);
    res.json({ message: 'Item added to cart', ...updatedCart });
  } catch (error) {
    logger.error('Add to cart error', { error: error.message, user_id: req.user.id, itemId, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to add item to cart' });
  }
});

// Get cart
router.get('/cart', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const cartData = await getCart(req.user.id);
    logger.info(`Fetched cart for user: ${req.user.id}`, { itemCount: cartData.items.length, user_id: req.user.id });
    res.json(cartData);
  } catch (error) {
    logger.error('Fetch cart error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch cart' });
  }
});

// Helper: Get cart data
const getCart = async (user_id) => {
  const [rows] = await withRetry(async () => {
    return await pool.execute(
      `SELECT c.id, c.itemId, c.quantity, c.couponId, m.name, m.price, m.image
       FROM cart c
       JOIN menu_items m ON c.itemId = m.id
       WHERE c.user_id = ?`,
      [user_id]
    );
  });

  let discount = 0;
  let couponId = null;
  if (rows.length && rows[0].couponId) {
    const [couponRows] = await withRetry(async () => {
      return await pool.execute('SELECT id, discount FROM coupons WHERE id = ? AND active = 1', [rows[0].couponId]);
    });
    if (couponRows.length) {
      const subtotal = rows.reduce((sum, item) => sum + item.price * item.quantity, 0);
      discount = subtotal * (couponRows[0].discount / 100);
      couponId = couponRows[0].id;
    }
  }
  return { items: rows, discount, couponId };
};

// Update cart quantity
router.post('/cart/update', authenticateToken, async (req, res) => {
  const { itemId, quantity } = req.body;
  if (!itemId || !Number.isInteger(quantity) || quantity < 0) {
    logger.warn('Update cart quantity failed: Invalid input', { user_id: req.user.id, itemId, quantity });
    return res.status(400).json({ message: 'Item ID and valid quantity are required' });
  }

  try {
    const sanitizedItemId = sanitizeInput(itemId);
    const [cartRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id FROM cart WHERE user_id = ? AND itemId = ?',
        [req.user.id, sanitizedItemId]
      );
    });

    if (!cartRows.length) {
      logger.warn(`Cart item not found: ${sanitizedItemId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Cart item not found' });
    }

    if (quantity === 0) {
      await withRetry(async () => {
        await pool.execute('DELETE FROM cart WHERE user_id = ? AND itemId = ?', [req.user.id, sanitizedItemId]);
      });
    } else {
      await withRetry(async () => {
        await pool.execute(
          'UPDATE cart SET quantity = ? WHERE user_id = ? AND itemId = ?',
          [quantity, req.user.id, sanitizedItemId]
        );
      });
    }

    logger.info(`Updated cart quantity: ${sanitizedItemId}, quantity: ${quantity}`, { user_id: req.user.id });
    const updatedCart = await getCart(req.user.id);
    res.json({ message: 'Quantity updated', ...updatedCart });
  } catch (error) {
    logger.error('Update cart quantity error', { error: error.message, user_id: req.user.id, itemId, quantity, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to update quantity' });
  }
});

// Remove item from cart
router.post('/cart/remove', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) {
    logger.warn('Remove from cart failed: Item ID missing', { user_id: req.user.id });
    return res.status(400).json({ message: 'Item ID is required' });
  }

  try {
    const sanitizedItemId = sanitizeInput(itemId);
    const [cartRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id FROM cart WHERE user_id = ? AND itemId = ?',
        [req.user.id, sanitizedItemId]
      );
    });

    if (!cartRows.length) {
      logger.warn(`Cart item not found: ${sanitizedItemId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Cart item not found' });
    }

    await withRetry(async () => {
      await pool.execute('DELETE FROM cart WHERE user_id = ? AND itemId = ?', [req.user.id, sanitizedItemId]);
    });

    logger.info(`Removed item from cart: ${sanitizedItemId}`, { user_id: req.user.id });
    const updatedCart = await getCart(req.user.id);
    res.json({ message: 'Item removed from cart', ...updatedCart });
  } catch (error) {
    logger.error('Remove from cart error', { error: error.message, user_id: req.user.id, itemId, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to remove item' });
  }
});

// Clear cart
router.post('/cart/clear', authenticateToken, async (req, res) => {
  try {
    await withRetry(async () => {
      await pool.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    });
    logger.info(`Cleared cart for user: ${req.user.id}`, { user_id: req.user.id });
    res.json({ message: 'Cart cleared', items: [], discount: 0, couponId: null });
  } catch (error) {
    logger.error('Clear cart error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to clear cart' });
  }
});

// Apply coupon to cart
router.post('/cart/apply-coupon', authenticateToken, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) {
    logger.warn('Apply coupon failed: Coupon code missing', { user_id: req.user.id });
    return res.status(400).json({ message: 'Coupon code is required' });
  }

  try {
    const sanitizedCouponCode = sanitizeInput(couponCode);
    const [couponRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, discount FROM coupons WHERE code = ? AND active = 1 AND (user_id IS NULL OR user_id = ?)',
        [sanitizedCouponCode, req.user.id]
      );
    });

    if (!couponRows.length) {
      logger.warn(`Invalid coupon: ${sanitizedCouponCode}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Invalid or expired coupon' });
    }

    const cartData = await getCart(req.user.id);
    if (!cartData.items.length) {
      logger.warn('Apply coupon failed: Cart is empty', { user_id: req.user.id });
      return res.status(400).json({ message: 'Cart is empty' });
    }

    await withRetry(async () => {
      await pool.execute('UPDATE cart SET couponId = ? WHERE user_id = ?', [couponRows[0].id, req.user.id]);
    });

    const updatedCart = await getCart(req.user.id);
    logger.info(`Applied coupon: ${sanitizedCouponCode}`, { user_id: req.user.id, discount: updatedCart.discount });
    res.json({ message: 'Coupon applied', ...updatedCart });
  } catch (error) {
    logger.error('Apply coupon error', { error: error.message, user_id: req.user.id, couponCode, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to apply coupon' });
  }
});

// Place order
router.post('/orders/place', authenticateToken, async (req, res) => {
  const { addressId, couponCode, items } = req.body;
  if (!addressId || !items || !Array.isArray(items) || items.length === 0) {
    logger.warn('Place order failed: Invalid input', { user_id: req.user.id, addressId, itemCount: items?.length });
    return res.status(400).json({ message: 'Address ID and valid items are required' });
  }

  try {
    const sanitizedAddressId = sanitizeInput(addressId);
    const cartData = await getCart(req.user.id);
    if (!cartData.items.length) {
      logger.warn('Place order failed: Cart is empty', { user_id: req.user.id });
      return res.status(400).json({ message: 'Cart is empty' });
    }

    let total = cartData.items.reduce((sum, item) => sum + item.price * item.quantity, 0);
    let couponId = null;
    if (couponCode) {
      const sanitizedCouponCode = sanitizeInput(couponCode);
      const [couponRows] = await withRetry(async () => {
        return await pool.execute(
          'SELECT id, discount FROM coupons WHERE code = ? AND active = 1 AND (user_id IS NULL OR user_id = ?)',
          [sanitizedCouponCode, req.user.id]
        );
      });
      if (couponRows.length) {
        couponId = couponRows[0].id;
        total = total * (1 - couponRows[0].discount / 100);
      }
    }

    const [addressRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, flat, street, landmark, phone FROM addresses WHERE id = ? AND user_id = ?',
        [sanitizedAddressId, req.user.id]
      );
    });
    if (!addressRows.length) {
      logger.warn(`Invalid address: ${sanitizedAddressId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Invalid address' });
    }

    const address = addressRows[0];
    const addressString = `${address.name}, ${address.flat}, ${address.street}${address.landmark ? `, ${address.landmark}` : ''}, ${address.phone}`;

    const [result] = await withRetry(async () => {
      return await pool.execute(
        'INSERT INTO orders (user_id, addressId, couponId, total, status, address, createdAt) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [req.user.id, sanitizedAddressId, couponId, total, 'PLACED', addressString]
      );
    });

    const orderId = result.insertId;
    const orderItems = cartData.items.map(item => [orderId, item.itemId, item.quantity]);
    await withRetry(async () => {
      await pool.query('INSERT INTO order_items (orderId, itemId, quantity) VALUES ?', [orderItems]);
    });

    await withRetry(async () => {
      await pool.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    });

    logger.info(`Order placed: ${orderId}`, { user_id: req.user.id, total, addressId: sanitizedAddressId });
    res.json({ message: 'Order placed successfully', orderId, total });
  } catch (error) {
    logger.error('Place order error', { error: error.message, user_id: req.user.id, addressId, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to place order' });
  }
});

// Get addresses
router.get('/addresses', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, phone, flat, street, landmark FROM addresses WHERE user_id = ?',
        [req.user.id]
      );
    });
    logger.info(`Fetched addresses for user: ${req.user.id}`, { count: rows.length, user_id: req.user.id });
    res.json({ addresses: rows });
  } catch (error) {
    logger.error('Fetch addresses error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch addresses' });
  }
});

// Add address
router.post('/addresses/add', authenticateToken, async (req, res) => {
  const { name, phone, flat, street, landmark } = req.body;
  if (!name || !phone || !flat || !street) {
    logger.warn('Add address failed: Required fields missing', { user_id: req.user.id });
    return res.status(400).json({ message: 'Name, phone, flat, and street are required' });
  }

  try {
    const sanitizedInput = {
      name: sanitizeInput(name),
      phone: sanitizeInput(phone),
      flat: sanitizeInput(flat),
      street: sanitizeInput(street),
      landmark: sanitizeInput(landmark || '')
    };

    await withRetry(async () => {
      await pool.execute(
        'INSERT INTO addresses (user_id, name, phone, flat, street, landmark) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, sanitizedInput.name, sanitizedInput.phone, sanitizedInput.flat, sanitizedInput.street, sanitizedInput.landmark || null]
      );
    });

    logger.info(`Added address for user: ${req.user.id}`, { user_id: req.user.id });
    const [newAddresses] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, phone, flat, street, landmark FROM addresses WHERE user_id = ?',
        [req.user.id]
      );
    });
    res.json({ message: 'Address added', addresses: newAddresses });
  } catch (error) {
    logger.error('Add address error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to add address' });
  }
});

// Update address
router.post('/addresses/update', authenticateToken, async (req, res) => {
  const { id, name, phone, flat, street, landmark } = req.body;
  if (!id || !name || !phone || !flat || !street) {
    logger.warn('Update address failed: Required fields missing', { user_id: req.user.id, addressId: id });
    return res.status(400).json({ message: 'ID, name, phone, flat, and street are required' });
  }

  try {
    const sanitizedId = sanitizeInput(id);
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id FROM addresses WHERE id = ? AND user_id = ?',
        [sanitizedId, req.user.id]
      );
    });
    if (!rows.length) {
      logger.warn(`Address not found: ${sanitizedId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Address not found' });
    }

    const sanitizedInput = {
      name: sanitizeInput(name),
      phone: sanitizeInput(phone),
      flat: sanitizeInput(flat),
      street: sanitizeInput(street),
      landmark: sanitizeInput(landmark || '')
    };

    await withRetry(async () => {
      await pool.execute(
        'UPDATE addresses SET name = ?, phone = ?, flat = ?, street = ?, landmark = ? WHERE id = ? AND user_id = ?',
        [sanitizedInput.name, sanitizedInput.phone, sanitizedInput.flat, sanitizedInput.street, sanitizedInput.landmark || null, sanitizedId, req.user.id]
      );
    });

    logger.info(`Updated address: ${sanitizedId}`, { user_id: req.user.id });
    const [updatedAddresses] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, phone, flat, street, landmark FROM addresses WHERE user_id = ?',
        [req.user.id]
      );
    });
    res.json({ message: 'Address updated', addresses: updatedAddresses });
  } catch (error) {
    logger.error('Update address error', { error: error.message, user_id: req.user.id, addressId: id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to update address' });
  }
});

// Delete address
router.post('/addresses/delete', authenticateToken, async (req, res) => {
  const { id } = req.body;
  if (!id) {
    logger.warn('Delete address failed: Address ID missing', { user_id: req.user.id });
    return res.status(400).json({ message: 'Address ID is required' });
  }

  try {
    const sanitizedId = sanitizeInput(id);
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id FROM addresses WHERE id = ? AND user_id = ?',
        [sanitizedId, req.user.id]
      );
    });
    if (!rows.length) {
      logger.warn(`Address not found: ${sanitizedId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Address not found' });
    }

    await withRetry(async () => {
      await pool.execute('DELETE FROM addresses WHERE id = ? AND user_id = ?', [sanitizedId, req.user.id]);
    });

    logger.info(`Deleted address: ${sanitizedId}`, { user_id: req.user.id });
    const [updatedAddresses] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, phone, flat, street, landmark FROM addresses WHERE user_id = ?',
        [req.user.id]
      );
    });
    res.json({ message: 'Address deleted', addresses: updatedAddresses });
  } catch (error) {
    logger.error('Delete address error', { error: error.message, user_id: req.user.id, addressId: id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to delete address' });
  }
});

// Toggle favourite
router.post('/favourites/toggle', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) {
    logger.warn('Toggle favourite failed: Item ID missing', { user_id: req.user.id });
    return res.status(400).json({ message: 'Item ID is required' });
  }

  try {
    const sanitizedItemId = sanitizeInput(itemId);
    const [itemRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id FROM menu_items WHERE id = ? AND active = 1',
        [sanitizedItemId]
      );
    });
    if (!itemRows.length) {
      logger.warn(`Item not found: ${sanitizedItemId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Item not found' });
    }

    const [favRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id FROM favourites WHERE user_id = ? AND itemId = ?',
        [req.user.id, sanitizedItemId]
      );
    });

    if (favRows.length) {
      await withRetry(async () => {
        await pool.execute('DELETE FROM favourites WHERE user_id = ? AND itemId = ?', [req.user.id, sanitizedItemId]);
      });
      logger.info(`Removed item from favourites: ${sanitizedItemId}`, { user_id: req.user.id });
    } else {
      await withRetry(async () => {
        await pool.execute('INSERT INTO favourites (user_id, itemId) VALUES (?, ?)', [req.user.id, sanitizedItemId]);
      });
      logger.info(`Added item to favourites: ${sanitizedItemId}`, { user_id: req.user.id });
    }

    const [updatedFavourites] = await withRetry(async () => {
      return await pool.execute(
        `SELECT m.id, m.name, m.price, m.image, m.description
         FROM favourites f
         JOIN menu_items m ON f.itemId = m.id
         WHERE f.user_id = ?`,
        [req.user.id]
      );
    });

    res.json({ message: favRows.length ? 'Removed from favourites' : 'Added to favourites', items: updatedFavourites });
  } catch (error) {
    logger.error('Toggle favourite error', { error: error.message, user_id: req.user.id, itemId, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to update favourites' });
  }
});

// Get favourites
router.get('/favourites', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        `SELECT m.id, m.name, m.price, m.image, m.description
         FROM favourites f
         JOIN menu_items m ON f.itemId = m.id
         WHERE f.user_id = ?`,
        [req.user.id]
      );
    });
    logger.info(`Fetched favourites for user: ${req.user.id}`, { count: rows.length, user_id: req.user.id });
    res.json({ items: rows });
  } catch (error) {
    logger.error('Fetch favourites error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch favourites' });
  }
});

// Update profile image
router.post('/profile/image', authenticateToken, upload.single('image'), handleMulterError, async (req, res) => {
  if (!req.file) {
    logger.warn('Profile image upload failed: No file uploaded', { user_id: req.user.id });
    return res.status(400).json({ message: 'No file uploaded' });
  }

  try {
    const imagePath = `/Uploads/${req.file.filename}`;
    await withRetry(async () => {
      await pool.execute('UPDATE users SET profileImage = ? WHERE id = ?', [imagePath, req.user.id]);
    });
    logger.info(`Updated profile image for user: ${req.user.id}`, { imagePath, user_id: req.user.id });
    res.json({ message: 'Profile image updated', profileImage: imagePath });
  } catch (error) {
    logger.error('Profile image upload error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to upload image' });
  }
});

// Update profile
router.post('/profile/update', authenticateToken, async (req, res) => {
  const { name, phone } = req.body;
  if (!name) {
    logger.warn('Update profile failed: Name is required', { user_id: req.user.id });
    return res.status(400).json({ message: 'Name is required' });
  }

  try {
    const sanitizedInput = {
      name: sanitizeInput(name),
      phone: phone ? sanitizeInput(phone) : null
    };
    await withRetry(async () => {
      await pool.execute('UPDATE users SET name = ?, phone = ? WHERE id = ? AND role = ?', [sanitizedInput.name, sanitizedInput.phone, req.user.id, 'user']);
    });
    logger.info(`Updated profile for user: ${req.user.id}`, { user_id: req.user.id });
    const [userRows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id, name, email, phone, profileImage, googleUser, role FROM users WHERE id = ? AND role = ?',
        [req.user.id, 'user']
      );
    });
    if (!userRows.length) {
      logger.warn(`User not found or not a customer: ${req.user.id}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'User not found or unauthorized role' });
    }
    res.json({ message: 'Profile updated', user: userRows[0] });
  } catch (error) {
    logger.error('Update profile error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

// Get active orders
router.get('/orders/active', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [orders] = await withRetry(async () => {
      return await pool.execute(
        `SELECT o.id, o.total, o.status, o.address, o.createdAt, o.cancelReason,
                CASE 
                  WHEN o.status = 'PLACED' THEN 'Confirmed'
                  WHEN o.status = 'SHIPPED' THEN 'Shipped'
                  WHEN o.status = 'DELIVERED' THEN 'Delivered'
                  ELSE o.status
                END as displayStatus
         FROM orders o
         WHERE o.user_id = ? AND o.status NOT IN ('DELIVERED', 'CANCELLED')
         ORDER BY o.createdAt DESC`,
        [req.user.id]
      );
    });

    const orderDetails = await Promise.all(orders.map(async (order) => {
      const [items] = await withRetry(async () => {
        return await pool.execute(
          `SELECT oi.itemId, oi.quantity, m.name, m.price, m.image
           FROM order_items oi
           JOIN menu_items m ON oi.itemId = m.id
           WHERE oi.orderId = ?`,
          [order.id]
        );
      });
      return { ...order, items, createdAt: new Date(order.createdAt).toISOString() };
    }));

    logger.info(`Fetched active orders for user: ${req.user.id}`, { count: orderDetails.length, user_id: req.user.id });
    res.json({ orders: orderDetails });
  } catch (error) {
    logger.error('Fetch active orders error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch active orders' });
  }
});

// Cancel order
router.post('/orders/cancel', authenticateToken, async (req, res) => {
  const { orderId, reason } = req.body;
  if (!orderId || !reason) {
    logger.warn('Cancel order failed: Order ID or reason missing', { user_id: req.user.id, orderId });
    return res.status(400).json({ message: 'Order ID and reason are required' });
  }

  try {
    const sanitizedOrderId = sanitizeInput(orderId);
    const [rows] = await withRetry(async () => {
      return await pool.execute(
        'SELECT id FROM orders WHERE id = ? AND user_id = ? AND status = ?',
        [sanitizedOrderId, req.user.id, 'PLACED']
      );
    });
    if (!rows.length) {
      logger.warn(`Order not found or cannot be cancelled: ${sanitizedOrderId}`, { user_id: req.user.id });
      return res.status(404).json({ message: 'Order not found or cannot be cancelled' });
    }

    await withRetry(async () => {
      await pool.execute(
        'UPDATE orders SET status = ?, cancelReason = ? WHERE id = ? AND user_id = ?',
        ['CANCELLED', sanitizeInput(reason), sanitizedOrderId, req.user.id]
      );
    });

    logger.info(`Cancelled order: ${sanitizedOrderId}`, { user_id: req.user.id });
    res.json({ message: 'Order cancelled' });
  } catch (error) {
    logger.error('Cancel order error', { error: error.message, user_id: req.user.id, orderId, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to cancel order' });
  }
});

// Get order history
router.get('/orders/history', authenticateToken, async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const [orders] = await withRetry(async () => {
      return await pool.execute(
        `SELECT o.id, o.total, o.status, o.address, o.createdAt, o.cancelReason,
                CASE 
                  WHEN o.status = 'PLACED' THEN 'Confirmed'
                  WHEN o.status = 'SHIPPED' THEN 'Shipped'
                  WHEN o.status = 'DELIVERED' THEN 'Delivered'
                  WHEN o.status = 'CANCELLED' THEN 'Cancelled'
                  ELSE o.status
                END as displayStatus
         FROM orders o
         WHERE o.user_id = ?
         ORDER BY o.createdAt DESC`,
        [req.user.id]
      );
    });

    const orderDetails = await Promise.all(orders.map(async (order) => {
      const [items] = await withRetry(async () => {
        return await pool.execute(
          `SELECT oi.itemId, oi.quantity, m.name, m.price, m.image
           FROM order_items oi
           JOIN menu_items m ON oi.itemId = m.id
           WHERE oi.orderId = ?`,
          [order.id]
        );
      });
      return { ...order, items, createdAt: new Date(order.createdAt).toISOString() };
    }));

    logger.info(`Fetched order history for user: ${req.user.id}`, { count: orderDetails.length, user_id: req.user.id });
    res.json({ orders: orderDetails });
  } catch (error) {
    logger.error('Fetch order history error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to fetch order history' });
  }
});

// Clear order history
router.post('/orders/clear-history', authenticateToken, async (req, res) => {
  try {
    const [result] = await withRetry(async () => {
      return await pool.execute(
        'DELETE FROM orders WHERE user_id = ? AND status IN (?, ?)',
        [req.user.id, 'DELIVERED', 'CANCELLED']
      );
    });
    logger.info(`Cleared order history for user: ${req.user.id}`, { affectedRows: result.affectedRows, user_id: req.user.id });
    res.json({ message: 'Order history cleared' });
  } catch (error) {
    logger.error('Clear order history error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to clear order history' });
  }
});

// Notify admin
router.post('/notify-admin/:type', authenticateToken, async (req, res) => {
  const { type } = req.params;
  const { orderId, items, total, address, name, phone, flat, street, landmark } = req.body;

  try {
    if (type === 'order') {
      if (!orderId || !items || !total || !address) {
        logger.warn('Notify admin failed: Missing order details', { user_id: req.user.id, type });
        return res.status(400).json({ message: 'Order details are required' });
      }
      logger.info(`Admin notified for new order: ${orderId}`, { user_id: req.user.id, total, address });
    } else if (type === 'address') {
      if (!name || !phone || !flat || !street) {
        logger.warn('Notify admin failed: Missing address details', { user_id: req.user.id, type });
        return res.status(400).json({ message: 'Address details are required' });
      }
      logger.info(`Admin notified for new address`, { user_id: req.user.id, name, phone, flat, street, landmark });
    } else {
      logger.warn(`Invalid notification type: ${type}`, { user_id: req.user.id });
      return res.status(400).json({ message: 'Invalid notification type' });
    }
    res.json({ message: 'Admin notified' });
  } catch (error) {
    logger.error(`Notify admin error (${type})`, { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to notify admin' });
  }
});

// Logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
      const expiresAt = new Date(decoded.exp * 1000); // Convert JWT expiration to Date
      await withRetry(async () => {
        await pool.execute('INSERT INTO blacklisted_tokens (token, expiresAt) VALUES (?, ?)', [token, expiresAt]);
      });
      logger.info(`Token blacklisted for user: ${req.user.id}`, { user_id: req.user.id });
    }
    logger.info(`User logged out: ${req.user.id}`, { user_id: req.user.id });
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error', { error: error.message, user_id: req.user.id, sqlMessage: error.sqlMessage });
    res.status(500).json({ message: 'Failed to logout' });
  }
});

module.exports = router;