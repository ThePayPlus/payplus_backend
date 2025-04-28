require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Konfigurasi CORS - mengizinkan semua origin
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
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
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'payplus_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    
    req.user = user;
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
    
    res.json({
      message: 'Login berhasil',
      data: {
        phone: user.phone,
        name: user.name,
        email: user.email,
        balance: parseFloat(user.balance),
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
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
app.get('/api/profile/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
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

// Savings endpoints
app.post('/api/savings', async (req, res) => {
  try {
    const { phone, nama, deskripsi, target, terkumpul = 0 } = req.body;
    
    if (!phone || !nama || !target) {
      return res.status(400).json({ 
        message: 'Kolom phone, nama, dan target harus diisi' 
      });
    }
    
    // Check if user exists
    const [users] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
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

app.get('/api/savings/summary/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
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

// Bills endpoints
app.get('/api/bills/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
    // Check if user exists
    const [users] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
    }
    
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
app.get('/api/transactions/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
    // Check if user exists
    const [users] = await pool.query(
      'SELECT * FROM users WHERE phone = ?',
      [phone]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
    }
    
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
