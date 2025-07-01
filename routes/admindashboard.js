const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { body, validationResult } = require('express-validator');
const dotenv = require('dotenv');

dotenv.config();

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Initialize Multer for file uploads
const upload = multer({
    dest: 'Uploads/',
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only JPEG, PNG, GIF, or WebP images are allowed'));
        }
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

// Check if table exists
async function tableExists(db, tableName) {
    try {
        await db.execute(`SELECT 1 FROM \`${tableName}\` LIMIT 1`);
        return true;
    } catch (error) {
        if (error.code === 'ER_NO_SUCH_TABLE') {
            return false;
        }
        throw error;
    }
}

// Check if column exists
async function columnExists(db, tableName, columnName) {
    try {
        const safeColumnName = columnName.replace(/[^a-zA-Z0-9_]/g, '');
        const [columns] = await db.execute(`SHOW COLUMNS FROM \`${tableName}\` LIKE '${safeColumnName}'`);
        return columns.length > 0;
    } catch (error) {
        console.error(`Error checking column ${columnName} in ${tableName}:`, error);
        return false;
    }
}

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        if (user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
        req.user = user;
        next();
    });
};

// Validation middleware for menu items, coupons, and profile
const validateMenuItem = [
    body('name').notEmpty().withMessage('Item name is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
    body('category').isIn([
        'MOCKTAILS', 'JUICES', 'MAGGIE', 'PASTA', 'SHAKES',
        'WAFFLES', 'EXTRA TOPPINGS', 'FRENCH FRIES', 'DESSERTS',
        'VEG PIZZA', 'NON-VEG PIZZA'
    ]).withMessage('Invalid category')
];

const validateCoupon = [
    body('code').notEmpty().withMessage('Coupon code is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('discount').isFloat({ min: 0, max: 100 }).withMessage('Discount must be between 0 and 100')
];

const validateProfile = [
    body('name').notEmpty().withMessage('Name is required')
];

// Error handling for validation
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// Restaurant status route
router.get('/restaurant-status', async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const settingsTableExists = await tableExists(db, 'settings');
        if (!settingsTableExists) {
            return res.status(500).json({ message: 'Settings table not found' });
        }
        const hasKeyColumn = await columnExists(db, 'settings', 'key');
        if (!hasKeyColumn) {
            return res.status(500).json({ message: 'Settings table missing key column' });
        }
        const [settings] = await db.execute('SELECT value FROM settings WHERE `key` = ?', ['restaurant_status']);
        const restaurantStatus = settings[0]?.value || 'Closed';
        res.status(200).json({ message: `Restaurant is ${restaurantStatus.toLowerCase()}`, status: restaurantStatus.toLowerCase() });
    } catch (error) {
        console.error('Fetch restaurant status error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Toggle restaurant status
router.post('/restaurant-status', authenticateToken, async (req, res) => {
    const { status } = req.body;
    if (!['Open', 'Closed'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status' });
    }
    let db;
    try {
        db = await getDbConnection();
        const settingsTableExists = await tableExists(db, 'settings');
        if (!settingsTableExists) {
            return res.status(500).json({ message: 'Settings table not found' });
        }
        const hasKeyColumn = await columnExists(db, 'settings', 'key');
        if (!hasKeyColumn) {
            return res.status(500).json({ message: 'Settings table missing key column' });
        }
        await db.execute(
            'INSERT INTO settings (`key`, `value`, created_at, updated_at) VALUES (?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE `value` = ?, updated_at = NOW()',
            ['restaurant_status', status, status]
        );
        res.json({ message: 'Restaurant status updated' });
    } catch (error) {
        console.error('Toggle restaurant status error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Admin signup route
router.post('/signup', [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], handleValidationErrors, async (req, res) => {
    const { name, email, password } = req.body;
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const [existingEmail] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existingEmail.length > 0) {
            return res.status(400).json({ message: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const hasIsVerifiedColumn = await columnExists(db, 'users', 'is_verified');
        const hasRoleColumn = await columnExists(db, 'users', 'role');

        const query = hasIsVerifiedColumn && hasRoleColumn
            ? 'INSERT INTO users (name, email, password, is_verified, role) VALUES (?, ?, ?, ?, ?)'
            : hasIsVerifiedColumn
            ? 'INSERT INTO users (name, email, password, is_verified) VALUES (?, ?, ?, ?)'
            : hasRoleColumn
            ? 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)'
            : 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';

        const params = hasIsVerifiedColumn && hasRoleColumn
            ? [name, email, hashedPassword, 1, 'admin']
            : hasIsVerifiedColumn
            ? [name, email, hashedPassword, 1]
            : hasRoleColumn
            ? [name, email, hashedPassword, 'admin']
            : [name, email, hashedPassword];

        await db.execute(query, params);

        const html = `
            <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                <h2 style="color: #1a202c; font-family: 'Playfair Display', serif;">Welcome to Delicute Admin Portal!</h2>
                <p style="color: #4a5568;">Dear ${name},</p>
                <p style="color: #4a5568;">Your admin account has been created. Log in to manage orders, menus, and more.</p>
                <a href="${process.env.CLIENT_URL}/admin" style="display: inline-block; background-color: #d69e2e; color: #ffffff; padding: 10px 20px; border-radius: 5px; text-decoration: none; margin: 20px 0;">Log In Now</a>
                <p style="color: #4a5568;">Contact us at <a href="mailto:contactdelicute@gmail.com" style="color: #d69e2e;">contactdelicute@gmail.com</a>.</p>
                <p style="color: #4a5568; margin-top: 20px;">Best regards,<br>The Delicute Team</p>
                <p style="color: #718096; font-size: 12px; text-align: center;">© 2025 Delicute.</p>
            </div>
        `;

        const sent = await sendEmail(email, 'Delicute - Welcome to Admin Portal!', html);
        if (!sent) {
            return res.status(500).json({ message: 'Account created, but failed to send welcome email.' });
        }

        res.status(200).json({ message: 'Admin sign up successful. Please log in.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Admin login route
router.post('/login', [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required')
], handleValidationErrors, async (req, res) => {
    const { email, password } = req.body;
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const hasRoleColumn = await columnExists(db, 'users', 'role');
        const hasIsVerifiedColumn = await columnExists(db, 'users', 'is_verified');
        const query = hasRoleColumn && hasIsVerifiedColumn
            ? 'SELECT * FROM users WHERE email = ? AND role = ? AND is_verified = ?'
            : hasRoleColumn
            ? 'SELECT * FROM users WHERE email = ? AND role = ?'
            : 'SELECT * FROM users WHERE email = ?';
        const params = hasRoleColumn && hasIsVerifiedColumn
            ? [email, 'admin', 1]
            : hasRoleColumn
            ? [email, 'admin']
            : [email];

        const [users] = await db.execute(query, params);
        if (users.length === 0) {
            return res.status(400).json({ message: 'Admin not found.' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid password.' });
        }

        const token = jwt.sign({ id: user.id, role: user.role || 'admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
        req.session.user = { id: user.id, role: user.role || 'admin' };
        res.status(200).json({ message: 'Admin login successful.', token, redirect: '/admindashboard' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Admin forgot password route
router.post('/forgot-password', [
    body('email').isEmail().withMessage('Valid email is required')
], handleValidationErrors, async (req, res) => {
    const { email } = req.body;
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const hasRoleColumn = await columnExists(db, 'users', 'role');
        const query = hasRoleColumn
            ? 'SELECT * FROM users WHERE email = ? AND role = ?'
            : 'SELECT * FROM users WHERE email = ?';
        const params = hasRoleColumn ? [email, 'admin'] : [email];

        const [users] = await db.execute(query, params);
        if (users.length === 0) {
            return res.status(400).json({ message: 'Admin email not registered.' });
        }

        const hasOtpColumns = await columnExists(db, 'users', 'otp') && await columnExists(db, 'users', 'otp_expires');
        if (!hasOtpColumns) {
            return res.status(500).json({ message: 'OTP functionality not supported.' });
        }

        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await db.execute('UPDATE users SET otp = ?, otp_expires = ? WHERE email = ?', [otp, otpExpires, email]);

        const html = `
            <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                <h2 style="color: #1a202c; font-family: 'Playfair Display', serif;">Delicute - Admin Password Reset Request</h2>
                <p style="color: #4a5568;">Dear ${users[0].name},</p>
                <p style="color: #4a5568;">Use the following OTP to reset your password:</p>
                <h3 style="color: #d69e2e; font-size: 24px; text-align: center; margin: 20px 0;">${otp}</h3>
                <p style="color: #4a5568;">Valid for 10 minutes. Contact <a href="mailto:contactdelicute@gmail.com" style="color: #d69e2e;">contactdelicute@gmail.com</a> if you did not request this.</p>
                <p style="color: #4a5568; margin-top: 20px;">Best regards,<br>The Delicute Team</p>
                <p style="color: #718096; font-size: 12px; text-align: center;">© 2025 Delicute.</p>
            </div>
        `;

        const sent = await sendEmail(email, 'Delicute - Reset Your Admin Password', html);
        if (!sent) {
            return res.status(500).json({ message: 'Failed to send OTP email.' });
        }

        res.status(200).json({ message: 'OTP sent to your email.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Admin reset password route
router.post('/reset-password', [
    body('email').isEmail().withMessage('Valid email is required'),
    body('otp').notEmpty().withMessage('OTP is required'),
    body('newPassword').optional().isLength({ min: 6 }).withMessage('New password must be at least 6 characters'),
    body('confirmPassword').optional().custom((value, { req }) => {
        if (value !== req.body.newPassword) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], handleValidationErrors, async (req, res) => {
    const { email, otp, newPassword, confirmPassword } = req.body;
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const hasOtpColumns = await columnExists(db, 'users', 'otp') && await columnExists(db, 'users', 'otp_expires');
        if (!hasOtpColumns) {
            return res.status(500).json({ message: 'OTP functionality not supported.' });
        }

        const hasRoleColumn = await columnExists(db, 'users', 'role');
        const query = hasRoleColumn
            ? 'SELECT * FROM users WHERE email = ? AND role = ? AND otp = ? AND otp_expires > NOW()'
            : 'SELECT * FROM users WHERE email = ? AND otp = ? AND otp_expires > NOW()';
        const params = hasRoleColumn ? [email, 'admin', otp] : [email, otp];

        const [users] = await db.execute(query, params);
        if (users.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        if (newPassword && confirmPassword) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await db.execute('UPDATE users SET password = ?, otp = NULL, otp_expires = NULL WHERE email = ?', [hashedPassword, email]);
            res.status(200).json({ message: 'Admin password reset successfully.' });
        } else {
            res.status(200).json({ message: 'OTP verified successfully.' });
        }
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Admin profile route
router.get('/profile', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const hasProfileImageColumn = await columnExists(db, 'users', 'profile_image');
        const hasRoleColumn = await columnExists(db, 'users', 'role');
        let query;
        if (hasProfileImageColumn && hasRoleColumn) {
            query = 'SELECT id, name, email, profile_image AS profileImage FROM users WHERE id = ? AND role = ?';
        } else if (hasProfileImageColumn) {
            query = 'SELECT id, name, email, profile_image AS profileImage FROM users WHERE id = ?';
        } else if (hasRoleColumn) {
            query = 'SELECT id, name, email FROM users WHERE id = ? AND role = ?';
        } else {
            query = 'SELECT id, name, email FROM users WHERE id = ?';
        }
        const params = hasRoleColumn ? [req.user.id, 'admin'] : [req.user.id];

        const [rows] = await db.execute(query, params);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Admin not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Fetch admin data error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Update admin profile
router.post('/profile/update', authenticateToken, validateProfile, handleValidationErrors, async (req, res) => {
    const { name } = req.body;
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const hasRoleColumn = await columnExists(db, 'users', 'role');
        const query = hasRoleColumn
            ? 'UPDATE users SET name = ? WHERE id = ? AND role = ?'
            : 'UPDATE users SET name = ? WHERE id = ?';
        const params = hasRoleColumn ? [name, req.user.id, 'admin'] : [name, req.user.id];

        await db.execute(query, params);
        res.json({ message: 'Profile updated' });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Update admin profile image
router.post('/profile/image', authenticateToken, upload.single('image'), async (req, res) => {
    let db;
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No image provided' });
        }
        db = await getDbConnection();
        const hasProfileImageColumn = await columnExists(db, 'users', 'profile_image');
        if (!hasProfileImageColumn) {
            return res.status(400).json({ message: 'Profile image upload not supported.' });
        }
        const result = await cloudinary.uploader.upload(req.file.path, {
            folder: 'delicute/profiles',
            public_id: `admin_${req.user.id}_${Date.now()}`
        });
        const hasRoleColumn = await columnExists(db, 'users', 'role');
        const query = hasRoleColumn
            ? 'UPDATE users SET profile_image = ? WHERE id = ? AND role = ?'
            : 'UPDATE users SET profile_image = ? WHERE id = ?';
        const params = hasRoleColumn ? [result.secure_url, req.user.id, 'admin'] : [result.secure_url, req.user.id];

        await db.execute(query, params);
        res.json({ message: 'Profile image updated' });
    } catch (error) {
        console.error('Upload profile image error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Dashboard stats route
router.get('/stats', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        const ordersQuery = hasDeletedAtColumn
            ? 'SELECT COUNT(*) as count FROM orders WHERE deleted_at IS NULL'
            : 'SELECT COUNT(*) as count FROM orders';
        const [orders] = await db.execute(ordersQuery);
        
        const hasIsActiveColumn = await columnExists(db, 'coupons', 'is_active');
        const couponsQuery = hasIsActiveColumn
            ? 'SELECT COUNT(*) as count FROM coupons WHERE is_active = 1'
            : 'SELECT COUNT(*) as count FROM coupons';
        const [coupons] = await db.execute(couponsQuery);
        
        const hasRoleColumn = await columnExists(db, 'users', 'role');
        let userCount;
        if (hasRoleColumn) {
            const [users] = await db.execute('SELECT COUNT(*) as count FROM users WHERE role IN (?, ?) AND is_blocked = 0', ['user', 'customer']);
            userCount = users[0].count;
        } else {
            const [users] = await db.execute('SELECT COUNT(*) as count FROM users WHERE is_blocked = 0');
            userCount = users[0].count;
        }

        const settingsTableExists = await tableExists(db, 'settings');
        let restaurantStatus = 'Closed';
        if (settingsTableExists) {
            const hasKeyColumn = await columnExists(db, 'settings', 'key');
            if (hasKeyColumn) {
                const [settings] = await db.execute('SELECT value FROM settings WHERE `key` = ?', ['restaurant_status']);
                restaurantStatus = settings[0]?.value || 'Closed';
            }
        }

        res.json({
            totalOrders: orders[0].count,
            totalUsers: userCount,
            totalCoupons: coupons[0].count,
            restaurantStatus
        });
    } catch (error) {
        console.error('Fetch stats error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Menu management routes
router.get('/menu', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'menu_items', 'deleted_at');
        const hasIsActiveColumn = await columnExists(db, 'menu_items', 'is_active');
        let query;
        if (hasDeletedAtColumn && hasIsActiveColumn) {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items WHERE deleted_at IS NULL AND is_active = 1';
        } else if (hasDeletedAtColumn) {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items WHERE deleted_at IS NULL';
        } else if (hasIsActiveColumn) {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items WHERE is_active = 1';
        } else {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items';
        }
        const [items] = await db.execute(query);
        const formattedItems = items.map(item => ({
            ...item,
            price: Number(item.price)
        }));
        res.json({ items: formattedItems });
    } catch (error) {
        console.error('Fetch menu items error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/menu/add', authenticateToken, upload.single('image'), validateMenuItem, handleValidationErrors, async (req, res) => {
    const { name, description, price, category } = req.body;
    let imageUrl = null;
    let db;
    try {
        db = await getDbConnection();
        if (req.file) {
            try {
                const result = await cloudinary.uploader.upload(req.file.path, {
                    folder: 'delicute/menu',
                    public_id: `menu_${Date.now()}`
                });
                imageUrl = result.secure_url;
            } catch (uploadError) {
                console.error('Cloudinary upload error:', uploadError);
                return res.status(500).json({ message: 'Failed to upload image to Cloudinary.', error: uploadError.message });
            }
        }
        const hasActiveColumn = await columnExists(db, 'menu_items', 'is_active');
        const query = hasActiveColumn
            ? 'INSERT INTO menu_items (name, description, price, category, image, is_active) VALUES (?, ?, ?, ?, ?, ?)'
            : 'INSERT INTO menu_items (name, description, price, category, image) VALUES (?, ?, ?, ?, ?)';
        const params = hasActiveColumn
            ? [name, description, price, category, imageUrl, 1]
            : [name, description, price, category, imageUrl];
        await db.execute(query, params);
        res.json({ message: 'Menu item added' });
    } catch (error) {
        console.error('Add menu item error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.get('/menu/:id', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'menu_items', 'deleted_at');
        const hasIsActiveColumn = await columnExists(db, 'menu_items', 'is_active');
        let query;
        if (hasDeletedAtColumn && hasIsActiveColumn) {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items WHERE id = ? AND deleted_at IS NULL AND is_active = 1';
        } else if (hasDeletedAtColumn) {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items WHERE id = ? AND deleted_at IS NULL';
        } else if (hasIsActiveColumn) {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items WHERE id = ? AND is_active = 1';
        } else {
            query = 'SELECT id, name, description, CAST(price AS DECIMAL(10,2)) AS price, category, image FROM menu_items WHERE id = ?';
        }
        const [rows] = await db.execute(query, [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Menu item not found' });
        }
        const formattedItem = {
            ...rows[0],
            price: Number(rows[0].price)
        };
        res.json(formattedItem);
    } catch (error) {
        console.error('Fetch menu item error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/menu/update', authenticateToken, upload.single('image'), validateMenuItem, handleValidationErrors, async (req, res) => {
    const { id, name, description, price, category } = req.body;
    let imageUrl = null;
    let db;
    try {
        db = await getDbConnection();
        if (req.file) {
            try {
                const result = await cloudinary.uploader.upload(req.file.path, {
                    folder: 'delicute/menu',
                    public_id: `menu_${Date.now()}`
                });
                imageUrl = result.secure_url;
            } catch (uploadError) {
                console.error('Cloudinary upload error:', uploadError);
                return res.status(500).json({ message: 'Failed to upload image to Cloudinary.', error: uploadError.message });
            }
        }
        const hasDeletedAtColumn = await columnExists(db, 'menu_items', 'deleted_at');
        const hasIsActiveColumn = await columnExists(db, 'menu_items', 'is_active');
        let query;
        if (hasDeletedAtColumn && hasIsActiveColumn) {
            query = 'UPDATE menu_items SET name = ?, description = ?, price = ?, category = ?, image = COALESCE(?, image) WHERE id = ? AND deleted_at IS NULL AND is_active = 1';
        } else if (hasDeletedAtColumn) {
            query = 'UPDATE menu_items SET name = ?, description = ?, price = ?, category = ?, image = COALESCE(?, image) WHERE id = ? AND deleted_at IS NULL';
        } else if (hasIsActiveColumn) {
            query = 'UPDATE menu_items SET name = ?, description = ?, price = ?, category = ?, image = COALESCE(?, image) WHERE id = ? AND is_active = 1';
        } else {
            query = 'UPDATE menu_items SET name = ?, description = ?, price = ?, category = ?, image = COALESCE(?, image) WHERE id = ?';
        }
        await db.execute(query, [name, description, price, category, imageUrl, id]);
        res.json({ message: 'Menu item updated' });
    } catch (error) {
        console.error('Update menu item error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/menu/delete', authenticateToken, async (req, res) => {
    const { id } = req.body;
    let db;
    try {
        db = await getDbConnection();
        await db.beginTransaction();
        
        // Delete related records from cart, favourites, and order_items
        await db.execute('DELETE FROM cart WHERE itemId = ?', [id]);
        await db.execute('DELETE FROM favourites WHERE itemId = ? OR item_id = ?', [id, id]);
        await db.execute('DELETE FROM order_items WHERE itemId = ?', [id]);
        
        // Permanently delete the menu item
        await db.execute('DELETE FROM menu_items WHERE id = ?', [id]);
        
        await db.commit();
        res.json({ message: 'Menu item permanently deleted' });
    } catch (error) {
        if (db) await db.rollback();
        console.error('Delete menu item error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Coupon management routes
router.get('/coupons', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasIsActiveColumn = await columnExists(db, 'coupons', 'is_active');
        const query = hasIsActiveColumn
            ? 'SELECT id, code, description, discount, image FROM coupons WHERE is_active = 1'
            : 'SELECT id, code, description, discount, image FROM coupons';
        const [coupons] = await db.execute(query);
        res.json({ coupons });
    } catch (error) {
        console.error('Fetch coupons error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/coupons/add', authenticateToken, upload.single('image'), validateCoupon, handleValidationErrors, async (req, res) => {
    const { code, description, discount } = req.body;
    let imageUrl = null;
    let db;
    try {
        db = await getDbConnection();
        if (req.file) {
            try {
                const result = await cloudinary.uploader.upload(req.file.path, {
                    folder: 'delicute/coupons',
                    public_id: `coupon_${Date.now()}`
                });
                imageUrl = result.secure_url;
            } catch (uploadError) {
                console.error('Cloudinary upload error:', uploadError);
                return res.status(500).json({ message: 'Failed to upload image to Cloudinary.', error: uploadError.message });
            }
        }
        const hasIsActiveColumn = await columnExists(db, 'coupons', 'is_active');
        const query = hasIsActiveColumn
            ? 'INSERT INTO coupons (code, description, discount, image, is_active) VALUES (?, ?, ?, ?, 1)'
            : 'INSERT INTO coupons (code, description, discount, image) VALUES (?, ?, ?, ?)';
        const params = [code, description, discount, imageUrl];
        await db.execute(query, params);
        res.json({ message: 'Coupon added' });
    } catch (error) {
        console.error('Add coupon error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.get('/coupons/:id', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasIsActiveColumn = await columnExists(db, 'coupons', 'is_active');
        const query = hasIsActiveColumn
            ? 'SELECT id, code, description, discount, image FROM coupons WHERE id = ? AND is_active = 1'
            : 'SELECT id, code, description, discount, image FROM coupons WHERE id = ?';
        const [rows] = await db.execute(query, [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Coupon not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Fetch coupon error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/coupons/update', authenticateToken, upload.single('image'), validateCoupon, handleValidationErrors, async (req, res) => {
    const { id, code, description, discount } = req.body;
    let imageUrl = null;
    let db;
    try {
        db = await getDbConnection();
        if (req.file) {
            try {
                const result = await cloudinary.uploader.upload(req.file.path, {
                    folder: 'delicute/coupons',
                    public_id: `coupon_${Date.now()}`
                });
                imageUrl = result.secure_url;
            } catch (uploadError) {
                console.error('Cloudinary upload error:', uploadError);
                return res.status(500).json({ message: 'Failed to upload image to Cloudinary.', error: uploadError.message });
            }
        }
        const hasIsActiveColumn = await columnExists(db, 'coupons', 'is_active');
        const query = hasIsActiveColumn
            ? 'UPDATE coupons SET code = ?, description = ?, discount = ?, image = COALESCE(?, image) WHERE id = ? AND is_active = 1'
            : 'UPDATE coupons SET code = ?, description = ?, discount = ?, image = COALESCE(?, image) WHERE id = ?';
        await db.execute(query, [code, description, discount, imageUrl, id]);
        res.json({ message: 'Coupon updated' });
    } catch (error) {
        console.error('Update coupon error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/coupons/delete', authenticateToken, async (req, res) => {
    const { id } = req.body;
    let db;
    try {
        db = await getDbConnection();
        await db.beginTransaction();
        
        // Delete related records from cart and orders
        await db.execute('DELETE FROM cart WHERE couponId = ?', [id]);
        await db.execute('UPDATE orders SET couponId = NULL WHERE couponId = ?', [id]);
        
        // Permanently delete the coupon
        await db.execute('DELETE FROM coupons WHERE id = ?', [id]);
        
        await db.commit();
        res.json({ message: 'Coupon permanently deleted' });
    } catch (error) {
        if (db) await db.rollback();
        console.error('Delete coupon error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// User management routes
router.get('/users', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const search = req.query.search || '';
        const hasRoleColumn = await columnExists(db, 'users', 'role');
        let query = hasRoleColumn
            ? 'SELECT id, name, email, phone, is_blocked AS isBlocked FROM users WHERE role IN (?, ?) AND is_blocked = 0'
            : 'SELECT id, name, email, phone, is_blocked AS isBlocked FROM users WHERE is_blocked = 0';
        let params = hasRoleColumn ? ['user', 'customer'] : [];

        if (search) {
            query += ' AND (name LIKE ? OR email LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }

        const [users] = await db.execute(query, params);
        res.json({ users });
    } catch (error) {
        console.error('Fetch users error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/users/block', authenticateToken, async (req, res) => {
    const { userId, block } = req.body;
    let db;
    try {
        db = await getDbConnection();
        const usersTableExists = await tableExists(db, 'users');
        if (!usersTableExists) {
            return res.status(500).json({ message: 'Users table not found.' });
        }

        const hasRoleColumn = await columnExists(db, 'users', 'role');
        const query = hasRoleColumn
            ? 'UPDATE users SET is_blocked = ? WHERE id = ? AND role IN (?, ?)'
            : 'UPDATE users SET is_blocked = ? WHERE id = ?';
        const params = hasRoleColumn ? [block ? 1 : 0, userId, 'user', 'customer'] : [block ? 1 : 0, userId];

        await db.execute(query, params);
        res.json({ message: `User ${block ? 'blocked' : 'unblocked'}` });
    } catch (error) {
        console.error('Toggle block user error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Order management routes
router.get('/orders', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const search = req.query.search || '';
        const status = req.query.status || '';
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        let query = `
            SELECT o.id, CAST(o.total AS DECIMAL(10,2)) AS total, o.status, u.name AS userName
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
        `;
        let params = [];
        if (hasDeletedAtColumn) {
            query += ' WHERE o.deleted_at IS NULL';
        }
        if (search) {
            query += hasDeletedAtColumn ? ' AND (o.id LIKE ? OR u.name LIKE ?)' : ' WHERE (o.id LIKE ? OR u.name LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
        if (status) {
            query += hasDeletedAtColumn || search ? ' AND o.status = ?' : ' WHERE o.status = ?';
            params.push(status);
        }
        const [orders] = await db.execute(query, params);
        const formattedOrders = orders.map(order => ({
            ...order,
            total: Number(order.total)
        }));
        res.json({ orders: formattedOrders });
    } catch (error) {
        console.error('Fetch orders error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.get('/orders/recent', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        const query = hasDeletedAtColumn
            ? `
                SELECT o.id, CAST(o.total AS DECIMAL(10,2)) AS total, o.status, u.name AS userName
                FROM orders o
                LEFT JOIN users u ON o.user_id = u.id
                WHERE o.deleted_at IS NULL
                ORDER BY o.createdAt DESC LIMIT 5
            `
            : `
                SELECT o.id, CAST(o.total AS DECIMAL(10,2)) AS total, o.status, u.name AS userName
                FROM orders o
                LEFT JOIN users u ON o.user_id = u.id
                ORDER BY o.createdAt DESC LIMIT 5
            `;
        const [orders] = await db.execute(query);
        const formattedOrders = orders.map(order => ({
            ...order,
            total: Number(order.total)
        }));
        res.json({ orders: formattedOrders });
    } catch (error) {
        console.error('Fetch recent orders error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.get('/orders/:id', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        const query = hasDeletedAtColumn
            ? `
                SELECT o.id, o.address, CAST(o.total AS DECIMAL(10,2)) AS total, o.status, o.couponId, u.name AS userName, u.email AS userEmail
                FROM orders o
                LEFT JOIN users u ON o.user_id = u.id
                WHERE o.id = ? AND o.deleted_at IS NULL
            `
            : `
                SELECT o.id, o.address, CAST(o.total AS DECIMAL(10,2)) AS total, o.status, o.couponId, u.name AS userName, u.email AS userEmail
                FROM orders o
                LEFT JOIN users u ON o.user_id = u.id
                WHERE o.id = ?
            `;
        const [orders] = await db.execute(query, [req.params.id]);
        if (orders.length === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }
        const [items] = await db.execute(
            `
            SELECT mi.name, oi.quantity, CAST(mi.price AS DECIMAL(10,2)) AS price
            FROM order_items oi
            JOIN menu_items mi ON oi.itemId = mi.id
            WHERE oi.orderId = ?
            `,
            [req.params.id]
        );
        const couponId = orders[0].couponId;
        let couponCode = null;
        if (couponId) {
            const [coupon] = await db.execute(
                'SELECT code FROM coupons WHERE id = ? AND is_active = 1',
                [couponId]
            );
            couponCode = coupon.length > 0 ? coupon[0].code : null;
        }
        const formattedOrder = {
            ...orders[0],
            total: Number(orders[0].total),
            couponCode,
            items: items.map(item => ({
                ...item,
                price: Number(item.price)
            }))
        };
        res.json({ order: formattedOrder });
    } catch (error) {
        console.error('Fetch order details error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/orders/update', authenticateToken, [
    body('orderId').notEmpty().withMessage('Order ID is required'),
    body('status').isIn(['PLACED', 'PROCESSING', 'SHIPPED', 'DELIVERED', 'CANCELLED']).withMessage('Invalid status')
], handleValidationErrors, async (req, res) => {
    const { orderId, status } = req.body;
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        const query = hasDeletedAtColumn
            ? 'UPDATE orders SET status = ? WHERE id = ? AND deleted_at IS NULL'
            : 'UPDATE orders SET status = ? WHERE id = ?';
        await db.execute(query, [status, orderId]);
        res.json({ message: 'Order status updated' });
    } catch (error) {
        console.error('Update order status error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/orders/delete', authenticateToken, async (req, res) => {
    const { orderIds } = req.body;
    if (!orderIds || !Array.isArray(orderIds) || orderIds.length === 0) {
        return res.status(400).json({ message: 'No orders selected' });
    }
    let db;
    try {
        db = await getDbConnection();
        await db.beginTransaction();
        
        // Delete related order_items first
        await db.execute(
            `DELETE FROM order_items WHERE orderId IN (${orderIds.map(() => '?').join(',')})`,
            orderIds
        );
        
        // Delete orders
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        const query = hasDeletedAtColumn
            ? `UPDATE orders SET deleted_at = NOW() WHERE id IN (${orderIds.map(() => '?').join(',')})`
            : `DELETE FROM orders WHERE id IN (${orderIds.map(() => '?').join(',')})`;
        await db.execute(query, orderIds);
        
        await db.commit();
        res.json({ message: 'Orders moved to trash' });
    } catch (error) {
        if (db) await db.rollback();
        console.error('Delete orders error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.get('/orders/trash', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        if (!hasDeletedAtColumn) {
            return res.json({ orders: [] });
        }
        const [orders] = await db.execute(
            `
            SELECT o.id, CAST(o.total AS DECIMAL(10,2)) AS total, o.status, o.deleted_at AS deletedAt, u.name AS userName
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            WHERE o.deleted_at IS NOT NULL
            `
        );
        const formattedOrders = orders.map(order => ({
            ...order,
            total: Number(order.total)
        }));
        res.json({ orders: formattedOrders });
    } catch (error) {
        console.error('Fetch trash error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/orders/restore', authenticateToken, async (req, res) => {
    const { orderIds } = req.body;
    if (!orderIds || !Array.isArray(orderIds) || orderIds.length === 0) {
        return res.status(400).json({ message: 'No orders selected' });
    }
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        if (!hasDeletedAtColumn) {
            return res.status(400).json({ message: 'Soft delete not supported' });
        }
        await db.execute(
            `UPDATE orders SET deleted_at = NULL WHERE id IN (${orderIds.map(() => '?').join(',')})`,
            orderIds
        );
        res.json({ message: 'Orders restored' });
    } catch (error) {
        console.error('Restore orders error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/orders/delete-permanent', authenticateToken, async (req, res) => {
    const { orderIds } = req.body;
    if (!orderIds || !Array.isArray(orderIds) || orderIds.length === 0) {
        return res.status(400).json({ message: 'No orders selected' });
    }
    let db;
    try {
        db = await getDbConnection();
        await db.beginTransaction();
        
        // Delete related order_items first
        await db.execute(
            `DELETE FROM order_items WHERE orderId IN (${orderIds.map(() => '?').join(',')})`,
            orderIds
        );
        
        // Delete orders
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        const query = hasDeletedAtColumn
            ? `DELETE FROM orders WHERE id IN (${orderIds.map(() => '?').join(',')}) AND deleted_at IS NOT NULL`
            : `DELETE FROM orders WHERE id IN (${orderIds.map(() => '?').join(',')})`;
        await db.execute(query, orderIds);
        
        await db.commit();
        res.json({ message: 'Orders permanently deleted' });
    } catch (error) {
        if (db) await db.rollback();
        console.error('Delete permanently orders error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

router.post('/orders/trash/clear', authenticateToken, async (req, res) => {
    let db;
    try {
        db = await getDbConnection();
        const hasDeletedAtColumn = await columnExists(db, 'orders', 'deleted_at');
        if (!hasDeletedAtColumn) {
            return res.json({ message: 'No trash to clear' });
        }
        await db.beginTransaction();
        const [orders] = await db.execute('SELECT id FROM orders WHERE deleted_at IS NOT NULL');
        const orderIds = orders.map(order => order.id);
        if (orderIds.length > 0) {
            await db.execute(
                `DELETE FROM order_items WHERE orderId IN (${orderIds.map(() => '?').join(',')})`,
                orderIds
            );
            await db.execute('DELETE FROM orders WHERE deleted_at IS NOT NULL');
        }
        await db.commit();
        res.json({ message: 'Trash cleared' });
    } catch (error) {
        if (db) await db.rollback();
        console.error('Clear trash error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    } finally {
        if (db) await db.end();
    }
});

// Admin logout route
router.post('/logout', authenticateToken, async (req, res) => {
    try {
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destroy error:', err);
                return res.status(500).json({ message: 'Failed to logout', error: err.message });
            }
            res.json({ message: 'Logged out successfully' });
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

// Custom 404 handler for this router
router.use((req, res) => {
    res.status(404).json({ message: 'Endpoint not found' });
});

module.exports = router;