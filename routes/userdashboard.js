const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');

// Database connection
async function getDBConnection() {
  return await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'delicute'
  });
}

// JWT authentication middleware
const authenticateToken = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(403).json({ message: 'Invalid token' });
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
    const filetypes = /jpeg|jpg|png/;
    const isValid = filetypes.test(path.extname(file.originalname).toLowerCase()) && filetypes.test(file.mimetype);
    if (isValid) return cb(null, true);
    cb(new Error('Images only (jpeg, jpg, png)'));
  },
  limits: { fileSize: 20 * 1024 * 1024 }
});

// Multer error handling
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    console.error(`File size error: ${err.message}, File: ${req.file?.originalname || 'unknown'}, Size: ${req.file?.size || 'unknown'} bytes`);
    return res.status(400).json({ message: 'File too large. Maximum size allowed is 20MB.' });
  }
  if (err) {
    console.error(`Multer error: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  next(err);
};

// Get user data
router.get('/user', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id, name, email, phone, profileImage, googleUser FROM users WHERE id = ?', [req.user.id]);
    await db.end();
    if (!rows.length) return res.status(404).json({ message: 'User not found' });
    res.json(rows[0]);
  } catch (error) {
    console.error('Fetch user error:', error.message);
    res.status(500).json({ message: 'Failed to fetch user data' });
  }
});

// Get total orders count
router.get('/orders/count', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT COUNT(*) as count FROM orders WHERE userId = ?', [req.user.id]);
    await db.end();
    res.json({ count: rows[0].count });
  } catch (error) {
    console.error('Fetch orders count error:', error.message);
    res.status(500).json({ message: 'Failed to fetch orders count' });
  }
});

// Get coupons
router.get('/coupons', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT code, description, image FROM coupons WHERE active = 1 AND (userId IS NULL OR userId = ?)', [req.user.id]);
    await db.end();
    res.json({ coupons: rows });
  } catch (error) {
    console.error('Fetch coupons error:', error.message);
    res.status(500).json({ message: 'Failed to fetch coupons' });
  }
});

// Get menu items
router.get('/menu', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id, name, price, category, image FROM menu_items WHERE active = 1');
    await db.end();
    res.json({ items: rows });
  } catch (error) {
    console.error('Fetch menu error:', error.message);
    res.status(500).json({ message: 'Failed to fetch menu' });
  }
});

// Add to cart
router.post('/cart/add', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) return res.status(400).json({ message: 'Item ID is required' });

  try {
    const db = await getDBConnection();
    const [itemRows] = await db.execute('SELECT id, name, price, image FROM menu_items WHERE id = ? AND active = 1', [itemId]);
    if (!itemRows.length) {
      await db.end();
      return res.status(404).json({ message: 'Item not found' });
    }

    const [cartRows] = await db.execute('SELECT id, quantity FROM cart WHERE userId = ? AND itemId = ?', [req.user.id, itemId]);
    if (cartRows.length) {
      await db.execute('UPDATE cart SET quantity = quantity + 1 WHERE id = ?', [cartRows[0].id]);
    } else {
      await db.execute('INSERT INTO cart (userId, itemId, quantity) VALUES (?, ?, 1)', [req.user.id, itemId]);
    }
    await db.end();
    res.json({ message: 'Item added to cart' });
  } catch (error) {
    console.error('Add to cart error:', error.message);
    res.status(500).json({ message: 'Failed to add item to cart' });
  }
});

// Get cart
router.get('/cart', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute(`
      SELECT c.id, c.itemId, c.quantity, c.couponId, m.name, m.price, m.image
      FROM cart c
      JOIN menu_items m ON c.itemId = m.id
      WHERE c.userId = ?
    `, [req.user.id]);

    let discount = 0;
    if (rows.length && rows[0].couponId) {
      const [couponRows] = await db.execute('SELECT discount FROM coupons WHERE id = ?', [rows[0].couponId]);
      if (couponRows.length) {
        const subtotal = rows.reduce((sum, item) => sum + item.price * item.quantity, 0);
        discount = subtotal * (couponRows[0].discount / 100);
      }
    }
    await db.end();
    res.json({ items: rows, discount });
  } catch (error) {
    console.error('Fetch cart error:', error.message);
    res.status(500).json({ message: 'Failed to fetch cart' });
  }
});

// Update cart quantity
router.post('/cart/update', authenticateToken, async (req, res) => {
  const { itemId, quantity } = req.body;
  if (!itemId || !quantity) return res.status(400).json({ message: 'Item ID and quantity are required' });

  try {
    const db = await getDBConnection();
    await db.execute('UPDATE cart SET quantity = ? WHERE userId = ? AND itemId = ?', [quantity, req.user.id, itemId]);
    await db.end();
    res.json({ message: 'Quantity updated' });
  } catch (error) {
    console.error('Update cart quantity error:', error.message);
    res.status(500).json({ message: 'Failed to update quantity' });
  }
});

// Remove from cart
router.post('/cart/remove', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) return res.status(400).json({ message: 'Item ID is required' });

  try {
    const db = await getDBConnection();
    await db.execute('DELETE FROM cart WHERE userId = ? AND itemId = ?', [req.user.id, itemId]);
    await db.end();
    res.json({ message: 'Item removed from cart' });
  } catch (error) {
    console.error('Remove from cart error:', error.message);
    res.status(500).json({ message: 'Failed to remove item' });
  }
});

// Clear cart
router.post('/cart/clear', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    await db.execute('DELETE FROM cart WHERE userId = ?', [req.user.id]);
    await db.end();
    res.json({ message: 'Cart cleared' });
  } catch (error) {
    console.error('Clear cart error:', error.message);
    res.status(500).json({ message: 'Failed to clear cart' });
  }
});

// Apply coupon to cart
router.post('/cart/apply-coupon', authenticateToken, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ message: 'Coupon code is required' });

  try {
    const db = await getDBConnection();
    const [couponRows] = await db.execute('SELECT id, discount FROM coupons WHERE code = ? AND active = 1 AND (userId IS NULL OR userId = ?)', [couponCode, req.user.id]);
    if (!couponRows.length) {
      await db.end();
      return res.status(404).json({ message: 'Invalid or expired coupon' });
    }

    const [cartRows] = await db.execute(`
      SELECT c.quantity, m.price
      FROM cart c
      JOIN menu_items m ON c.itemId = m.id
      WHERE c.userId = ?
    `, [req.user.id]);

    if (!cartRows.length) {
      await db.end();
      return res.status(400).json({ message: 'Cart is empty' });
    }

    const subtotal = cartRows.reduce((sum, item) => sum + item.price * item.quantity, 0);
    const discount = subtotal * (couponRows[0].discount / 100);

    await db.execute('UPDATE cart SET couponId = ? WHERE userId = ?', [couponRows[0].id, req.user.id]);
    await db.end();
    res.json({ message: 'Coupon applied', discount });
  } catch (error) {
    console.error('Apply coupon error:', error.message);
    res.status(500).json({ message: 'Failed to apply coupon' });
  }
});

// Place order
router.post('/orders/place', authenticateToken, async (req, res) => {
  const { addressId, couponCode } = req.body;
  if (!addressId) return res.status(400).json({ message: 'Address ID is required' });

  try {
    const db = await getDBConnection();
    const [cartRows] = await db.execute(`
      SELECT c.quantity, m.price
      FROM cart c
      JOIN menu_items m ON c.itemId = m.id
      WHERE c.userId = ?
    `, [req.user.id]);

    if (!cartRows.length) {
      await db.end();
      return res.status(400).json({ message: 'Cart is empty' });
    }

    let total = cartRows.reduce((sum, item) => sum + item.price * item.quantity, 0);
    let couponId = null;
    if (couponCode) {
      const [couponRows] = await db.execute('SELECT id, discount FROM coupons WHERE code = ? AND active = 1 AND (userId IS NULL OR userId = ?)', [couponCode, req.user.id]);
      if (couponRows.length) {
        couponId = couponRows[0].id;
        total = total * (1 - couponRows[0].discount / 100);
      }
    }

    const [addressRows] = await db.execute('SELECT id FROM addresses WHERE id = ? AND userId = ?', [addressId, req.user.id]);
    if (!addressRows.length) {
      await db.end();
      return res.status(404).json({ message: 'Invalid address' });
    }

    const [result] = await db.execute(
      'INSERT INTO orders (userId, addressId, couponId, total, status) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, addressId, couponId, total, 'PLACED']
    );

    await db.execute('INSERT INTO order_items (orderId, itemId, quantity) SELECT ?, itemId, quantity FROM cart WHERE userId = ?', [result.insertId, req.user.id]);
    await db.execute('DELETE FROM cart WHERE userId = ?', [req.user.id]);
    await db.end();
    res.json({ message: 'Order placed successfully' });
  } catch (error) {
    console.error('Place order error:', error.message);
    res.status(500).json({ message: 'Failed to place order' });
  }
});

// Get addresses
router.get('/addresses', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id, name, phone, flat, street, landmark FROM addresses WHERE userId = ?', [req.user.id]);
    await db.end();
    res.json({ addresses: rows });
  } catch (error) {
    console.error('Fetch addresses error:', error.message);
    res.status(500).json({ message: 'Failed to fetch addresses' });
  }
});

// Add address
router.post('/addresses/add', authenticateToken, async (req, res) => {
  const { name, phone, flat, street, landmark } = req.body;
  if (!name || !phone || !flat || !street) return res.status(400).json({ message: 'Required fields missing' });

  try {
    const db = await getDBConnection();
    await db.execute(
      'INSERT INTO addresses (userId, name, phone, flat, street, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, name, phone, flat, street, landmark || null]
    );
    await db.end();
    res.json({ message: 'Address added' });
  } catch (error) {
    console.error('Add address error:', error.message);
    res.status(500).json({ message: 'Failed to add address' });
  }
});

// Update address
router.post('/addresses/update', authenticateToken, async (req, res) => {
  const { id, name, phone, flat, street, landmark } = req.body;
  if (!id || !name || !phone || !flat || !street) return res.status(400).json({ message: 'Required fields missing' });

  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id FROM addresses WHERE id = ? AND userId = ?', [id, req.user.id]);
    if (!rows.length) {
      await db.end();
      return res.status(404).json({ message: 'Address not found' });
    }

    await db.execute(
      'UPDATE addresses SET name = ?, phone = ?, flat = ?, street = ?, landmark = ? WHERE id = ?',
      [name, phone, flat, street, landmark || null, id]
    );
    await db.end();
    res.json({ message: 'Address updated' });
  } catch (error) {
    console.error('Update address error:', error.message);
    res.status(500).json({ message: 'Failed to update address' });
  }
});

// Delete address
router.post('/addresses/delete', authenticateToken, async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'Address ID is required' });

  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id FROM addresses WHERE id = ? AND userId = ?', [id, req.user.id]);
    if (!rows.length) {
      await db.end();
      return res.status(404).json({ message: 'Address not found' });
    }

    await db.execute('DELETE FROM addresses WHERE id = ?', [id]);
    await db.end();
    res.json({ message: 'Address deleted' });
  } catch (error) {
    console.error('Delete address error:', error.message);
    res.status(500).json({ message: 'Failed to delete address' });
  }
});

// Toggle favourite
router.post('/favourites/toggle', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) return res.status(400).json({ message: 'Item ID is required' });

  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id FROM favourites WHERE userId = ? AND itemId = ?', [req.user.id, itemId]);
    if (rows.length) {
      await db.execute('DELETE FROM favourites WHERE userId = ? AND itemId = ?', [req.user.id, itemId]);
      res.json({ message: 'Removed from favourites' });
    } else {
      await db.execute('INSERT INTO favourites (userId, itemId) VALUES (?, ?)', [req.user.id, itemId]);
      res.json({ message: 'Added to favourites' });
    }
    await db.end();
  } catch (error) {
    console.error('Toggle favourite error:', error.message);
    res.status(500).json({ message: 'Failed to update favourites' });
  }
});

// Get favourites
router.get('/favourites', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute(`
      SELECT m.id, m.name, m.price, m.image
      FROM favourites f
      JOIN menu_items m ON f.itemId = m.id
      WHERE f.userId = ?
    `, [req.user.id]);
    await db.end();
    res.json({ items: rows });
  } catch (error) {
    console.error('Fetch favourites error:', error.message);
    res.status(500).json({ message: 'Failed to fetch favourites' });
  }
});

// Update profile image
router.post('/profile/image', authenticateToken, upload.single('image'), handleMulterError, async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

  try {
    const db = await getDBConnection();
    const imagePath = `/Uploads/${req.file.filename}`;
    await db.execute('UPDATE users SET profileImage = ? WHERE id = ?', [imagePath, req.user.id]);
    await db.end();
    res.json({ message: 'Profile image updated', profileImage: imagePath });
  } catch (error) {
    console.error('Profile image upload error:', error.message);
    res.status(500).json({ message: 'Failed to upload image' });
  }
});

// Update profile
router.post('/profile/update', authenticateToken, async (req, res) => {
  const { name, phone } = req.body;
  if (!name) return res.status(400).json({ message: 'Name is required' });

  try {
    const db = await getDBConnection();
    await db.execute('UPDATE users SET name = ?, phone = ? WHERE id = ?', [name, phone || null, req.user.id]);
    await db.end();
    res.json({ message: 'Profile updated' });
  } catch (error) {
    console.error('Update profile error:', error.message);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

// Get active orders
router.get('/orders/active', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id, total, status FROM orders WHERE userId = ? AND status NOT IN ("DELIVERED", "CANCELLED")', [req.user.id]);
    await db.end();
    res.json({ orders: rows });
  } catch (error) {
    console.error('Fetch active orders error:', error.message);
    res.status(500).json({ message: 'Failed to fetch active orders' });
  }
});

// Cancel order
router.post('/orders/cancel', authenticateToken, async (req, res) => {
  const { orderId, reason } = req.body;
  if (!orderId || !reason) return res.status(400).json({ message: 'Order ID and reason are required' });

  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id FROM orders WHERE id = ? AND userId = ? AND status = "PLACED"', [orderId, req.user.id]);
    if (!rows.length) {
      await db.end();
      return res.status(404).json({ message: 'Order not found or cannot be cancelled' });
    }

    await db.execute('UPDATE orders SET status = "CANCELLED", cancelReason = ? WHERE id = ?', [reason, orderId]);
    await db.end();
    res.json({ message: 'Order cancelled' });
  } catch (error) {
    console.error('Cancel order error:', error.message);
    res.status(500).json({ message: 'Failed to cancel order' });
  }
});

// Get order history
router.get('/orders/history', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute('SELECT id, total, status FROM orders WHERE userId = ?', [req.user.id]);
    await db.end();
    res.json({ orders: rows });
  } catch (error) {
    console.error('Fetch order history error:', error.message);
    res.status(500).json({ message: 'Failed to fetch order history' });
  }
});

// Clear order history
router.post('/orders/history/clear', authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    await db.execute('DELETE FROM orders WHERE userId = ? AND status IN ("DELIVERED", "CANCELLED")', [req.user.id]);
    await db.end();
    res.json({ message: 'Order history cleared' });
  } catch (error) {
    console.error('Clear order history error:', error.message);
    res.status(500).json({ message: 'Failed to clear order history' });
  }
});

// Logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    req.session?.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err.message);
        return res.status(500).json({ message: 'Failed to logout' });
      }
      res.json({ message: 'Logged out successfully' });
    });
  } catch (error) {
    console.error('Logout error:', error.message);
    res.status(500).json({ message: 'Failed to logout' });
  }
});

module.exports = router;