require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cookieParser());

// Konfigurasi CORS - mengizinkan origin yang spesifik untuk mendukung credentials
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173', // Ubah ke URL frontend Anda
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Enable credentials (cookies, authorization headers, etc.)
}));

// Database connection
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'payplus'
};

let pool;

async function initializeDb() {
  try {
    // Create connection pool
    pool = mysql.createPool(dbConfig);
    console.log('Database connection established');
  } catch (error) {
    console.error('Database initialization error:', error);
    process.exit(1);
  }
}

// Auth middleware
const authenticateToken = (req, res, next) => {
  // Check cookie first, then fallback to header
  let token = null;
  
  // Try to get token from cookie
  if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
    console.log('Using token from cookie');
  } 
  // Fallback to Authorization header
  else {
    const authHeader = req.headers['authorization'];
    console.log('Auth Header:', authHeader);
    
    if (authHeader) {
      token = authHeader.split(' ')[1];
      console.log('Using token from Authorization header');
    }
  }
  
  // No token found in either cookie or header
  if (!token) {
    return res.status(401).json({ 
      message: 'Authentication token required', 
      details: 'No token found in cookie or Authorization header' 
    });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'payplus_secret_key', (err, decoded) => {
    if (err) {
      console.log('Token verification error:', err);
      return res.status(403).json({ 
        message: 'Invalid or expired token',
        details: err.message 
      });
    }
    
    // Ensure the decoded token contains phone
    if (!decoded.phone) {
      return res.status(403).json({ 
        message: 'Invalid token format',
        details: 'Token does not contain phone number information'
      });
    }
    
    console.log('Auth successful for user:', decoded.phone);
    req.user = { phone: decoded.phone };
    next();
  });
};

// Routes

// Auth routes
// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    
    if (!phone || !password) {
      return res.status(400).json({ message: 'Nomor telepon dan password diperlukan' });
    }
    
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Login gagal. Nomor telepon atau password salah.' });
    }
    
    const user = rows[0];
    
    // Check if the password is already hashed
    const isHashed = user.password.startsWith('$2b$') || user.password.startsWith('$2a$');
    
    let isPasswordValid = false;
    if (isHashed) {
      // Compare with hashed password
      isPasswordValid = await bcrypt.compare(password, user.password);
    } else {
      // For backward compatibility - direct comparison
      isPasswordValid = user.password === password;
      
      // Update to hashed password if it matches
      if (isPasswordValid) {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await pool.query(
          'UPDATE users SET password = ? WHERE phone = ?',
          [hashedPassword, phone]
        );
        console.log(`Password hashed for user ${phone}`);
      }
    }
    
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Login gagal. Nomor telepon atau password salah.' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { phone: user.phone },
      process.env.JWT_SECRET || 'payplus_secret_key',
      { expiresIn: '24h' }
    );
    
    // Set the token as a cookie
    res.cookie('token', token, {
      httpOnly: true, // Prevents JavaScript access to the cookie
      secure: process.env.NODE_ENV === 'production', // Use secure in production
      sameSite: 'lax', // Helps prevent CSRF
      maxAge: 24 * 60 * 60 * 1000 // 24 hours in milliseconds
    });
    
    res.json({
      message: 'Login berhasil',
      data: {
        phone: user.phone,
        token // Still include token in response for client-side storage if needed
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout berhasil' });
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, email, password } = req.body;
    
    if (!phone || !name || !email || !password) {
      return res.status(400).json({ 
        message: 'Semua kolom (phone, name, email, password) harus diisi' 
      });
    }
    
    // Check if user already exists
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (existingUsers.length > 0) {
      return res.status(400).json({ 
        message: 'Registrasi gagal. Nomor telepon sudah terdaftar.' 
      });
    }
    
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Insert new user with hashed password
    await pool.query(
      'INSERT INTO users (phone, name, email, password, balance) VALUES (?, ?, ?, ?, ?)',
      [phone, name, email, hashedPassword, 0]
    );
    
    res.status(201).json({ message: 'Registrasi berhasil' });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Profile endpoint
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    
    const [rows] = await pool.query(
      'SELECT phone, name, email, balance FROM users WHERE phone = ?',
      [phone]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
    }
    
    res.json({
      phone: rows[0].phone,
      name: rows[0].name,
      email: rows[0].email,
      balance: parseFloat(rows[0].balance)
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update profile endpoint
app.patch('/api/profile', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const { name, email } = req.body;
    
    // Validate that at least one field is provided
    if (!name && !email) {
      return res.status(400).json({ 
        message: 'Setidaknya satu field (name atau email) harus diisi untuk update' 
      });
    }
    
    // Check if user exists
    const [userCheck] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (userCheck.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
    }
    
    // Build update query dynamically based on provided fields
    let updateQuery = 'UPDATE users SET ';
    const updateValues = [];
    
    if (name) {
      updateQuery += 'name = ?';
      updateValues.push(name);
    }
    
    if (email) {
      if (name) updateQuery += ', '; // Add comma if name was added
      updateQuery += 'email = ?';
      updateValues.push(email);
    }
    
    updateQuery += ' WHERE phone = ?';
    updateValues.push(phone);
    
    // Execute update query
    await pool.query(updateQuery, updateValues);
    
    // Get updated user data
    const [updatedUser] = await pool.query(
      'SELECT phone, name, email, balance FROM users WHERE phone = ?',
      [phone]
    );
    
    res.json({
      message: 'Profil berhasil diperbarui',
      data: {
        name: updatedUser[0].name,
        email: updatedUser[0].email,
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Change password endpoint
app.patch('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const { oldPassword, newPassword } = req.body;
    
    // Validate request
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ 
        message: 'Password lama dan password baru harus diisi' 
      });
    }
    
    // Check if new password meets requirements
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        message: 'Password baru harus minimal 6 karakter' 
      });
    }
    
    // Get user data to verify old password
    const [users] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
    }
    
    const user = users[0];
    
    // Verify old password
    const isHashed = user.password.startsWith('$2b$') || user.password.startsWith('$2a$');
    let isOldPasswordValid = false;
    
    if (isHashed) {
      // Compare with hashed password
      isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    } else {
      // Direct comparison for legacy passwords
      isOldPasswordValid = user.password === oldPassword;
    }
    
    if (!isOldPasswordValid) {
      return res.status(401).json({ message: 'Password lama tidak valid' });
    }
    
    // Hash new password
    const saltRounds = 10;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update password
    await pool.query(
      'UPDATE users SET password = ? WHERE phone = ?',
      [hashedNewPassword, phone]
    );
    
    res.json({ message: 'Password berhasil diubah' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Savings endpoints
app.post('/api/savings', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const { nama, deskripsi, target, terkumpul = 0 } = req.body;
    
    if (!nama || !target) {
      return res.status(400).json({ 
        message: 'Kolom nama dan target harus diisi' 
      });
    }
    
    await pool.query(
      'INSERT INTO savings (phone, nama, deskripsi, target, terkumpul) VALUES (?, ?, ?, ?, ?)',
      [phone, nama, deskripsi, target, terkumpul]
    );
    
    res.status(201).json({ message: 'Tabungan berhasil ditambahkan' });
  } catch (error) {
    console.error('Create savings error:', error);
    res.status(500).json({ message: 'Gagal menambahkan tabungan' });
  }
});

app.get('/api/savings/summary', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    
    // Check if user exists
    const [users] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
    }
    
    // Get savings summary
    const [result] = await pool.query(
      'SELECT SUM(target) as total_target, SUM(terkumpul) as total_terkumpul FROM savings WHERE phone = ?',
      [phone]
    );
    
    if (!result[0].total_target) {
      return res.json({ total_target: 0, total_terkumpul: 0 });
    }
    
    res.json({
      total_target: parseFloat(result[0].total_target),
      total_terkumpul: parseFloat(result[0].total_terkumpul || 0)
    });
  } catch (error) {
    console.error('Get savings summary error:', error);
    res.status(500).json({ message: 'Gagal mengambil data tabungan' });
  }
});

// Get all savings with summary
app.get('/api/savings', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    
    // Get summary of all savings
    const [summaryResult] = await pool.query(`
      SELECT 
        SUM(target) as total_target,
        SUM(terkumpul) as total_terkumpul
      FROM savings 
      WHERE phone = ?
    `, [phone]);
    
    // Get all savings records
    const [savingsRecords] = await pool.query(`
      SELECT 
        id,
        nama as namaSavings,
        deskripsi,
        target,
        terkumpul
      FROM savings
      WHERE phone = ?
      ORDER BY id ASC
    `, [phone]);
    
    // Format the response data
    const summary = {
      total_target: summaryResult[0].total_target ? parseInt(summaryResult[0].total_target).toString() : "0",
      total_terkumpul: summaryResult[0].total_terkumpul ? parseInt(summaryResult[0].total_terkumpul).toString() : "0"
    };
    
    const formattedRecords = savingsRecords.map(record => ({
      id: record.id,
      namaSavings: record.namaSavings,
      deskripsi: record.deskripsi || "",
      target: record.target.toString(),
      terkumpul: record.terkumpul.toString()
    }));
    
    res.json({
      summary: summary,
      records: formattedRecords
    });
  } catch (error) {
    console.error('Get savings error:', error);
    res.status(500).json({ message: 'Gagal mengambil data tabungan' });
  }
});

// Bills endpoints
app.get('/api/bills', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    
    // Get bills - the table is named 'bill' in the provided schema
    const [bills] = await pool.query(
      'SELECT id, name, amount, dueDate, category FROM bill WHERE phone = ?',
      [phone]
    );
    
    res.json({ bills });
  } catch (error) {
    console.error('Get bills error:', error);
    res.status(500).json({ message: 'Gagal mengambil data tagihan' });
  }
});

// Transactions endpoints
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    
    // Get income from income table
    const [income] = await pool.query(
      'SELECT amount, sender_phone, type, date FROM income WHERE phone = ?',
      [phone]
    );
    
    // Get expenses from expense table
    const [expense] = await pool.query(
      'SELECT amount, receiver_phone, type, date, message FROM expense WHERE phone = ?',
      [phone]
    );
    
    // Format the income data to match the expected format
    const formattedIncome = income.map(item => ({
      amount: parseFloat(item.amount),
      sender_phone: item.sender_phone.toString(),
      type: item.type,
      date: formatDate(item.date)
    }));
    
    // Format the expense data to match the expected format
    const formattedExpense = expense.map(item => ({
      amount: parseFloat(item.amount),
      receiver_phone: item.receiver_phone.toString(),
      type: item.type,
      date: formatDate(item.date),
      message: item.message
    }));
    
    res.json({ income: formattedIncome, expense: formattedExpense });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ message: 'Gagal mengambil data transaksi' });
  }
});

// Income record endpoint
app.get('/api/income-record', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    
    // Join income table with users table to get sender names
    const [incomeRecords] = await pool.query(`
      SELECT 
        i.amount, 
        i.sender_phone, 
        u.name AS sender, 
        i.type, 
        i.date, 
        i.message
      FROM income i
      LEFT JOIN users u ON i.sender_phone = u.phone
      WHERE i.phone = ?
      ORDER BY i.date DESC
    `, [phone]);
    
    // Get summary statistics
    const [summaryResults] = await pool.query(`
      SELECT 
        SUM(amount) as total_income,
        COUNT(*) as total_transactions,
        SUM(CASE WHEN type = 'normal' THEN amount ELSE 0 END) as total_normal,
        SUM(CASE WHEN type = 'gift' THEN amount ELSE 0 END) as total_gift,
        SUM(CASE WHEN type = 'topup' THEN amount ELSE 0 END) as total_topup,
        COUNT(CASE WHEN type = 'normal' THEN 1 END) as count_normal,
        COUNT(CASE WHEN type = 'gift' THEN 1 END) as count_gift,
        COUNT(CASE WHEN type = 'topup' THEN 1 END) as count_topup
      FROM income
      WHERE phone = ?
    `, [phone]);
    
    const summary = {
      total_income: summaryResults[0].total_income ? parseInt(summaryResults[0].total_income).toString() : "0",
      total_transactions: summaryResults[0].total_transactions,
      total_normal: summaryResults[0].total_normal ? parseInt(summaryResults[0].total_normal).toString() : "0",
      total_gift: summaryResults[0].total_gift ? parseInt(summaryResults[0].total_gift).toString() : "0",
      total_topup: summaryResults[0].total_topup ? parseInt(summaryResults[0].total_topup).toString() : "0",
      count_normal: summaryResults[0].count_normal || 0,
      count_gift: summaryResults[0].count_gift || 0,
      count_topup: summaryResults[0].count_topup || 0
    };
    
    // Format the response data
    const formattedRecords = incomeRecords.map(record => ({
      amount: record.amount.toString(),
      sender: record.sender || 'Unknown', // Handle case where sender might not be in users table
      type: record.type,
      message: record.message || ""
    }));
    
    res.json({
      summary: summary,
      records: formattedRecords
    });
  } catch (error) {
    console.error('Get income records error:', error);
    res.status(500).json({ message: 'Gagal mengambil data riwayat pendapatan' });
  }
});

// Test endpoint to check headers and cookies
app.get('/api/test-headers', (req, res) => {
  console.log('Received headers:', req.headers);
  console.log('Received cookies:', req.cookies);
  res.json({ 
    message: 'Headers and cookies received',
    headers: req.headers,
    cookies: req.cookies,
    authHeader: req.headers['authorization'],
    tokenCookie: req.cookies.token
  });
});

// Helper function to format date
function formatDate(date) {
  if (!date) return null;
  const d = new Date(date);
  return d.toISOString().split('T')[0]; // Format as YYYY-MM-DD
}

// Initialize database and start server
initializeDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize server:', err);
});
