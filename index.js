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
app.use(
  cors({
    origin: '*', // Ubah ke URL frontend Anda
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true, // Enable credentials (cookies, authorization headers, etc.)
  })
);

// Database connection
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'payplus',
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
      details: 'No token found in cookie or Authorization header',
    });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'payplus_secret_key', (err, decoded) => {
    if (err) {
      console.log('Token verification error:', err);
      return res.status(403).json({
        message: 'Invalid or expired token',
        details: err.message,
      });
    }

    // Ensure the decoded token contains phone
    if (!decoded.phone) {
      return res.status(403).json({
        message: 'Invalid token format',
        details: 'Token does not contain phone number information',
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

    const [rows] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);

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
        await pool.query('UPDATE users SET password = ? WHERE phone = ?', [hashedPassword, phone]);
        console.log(`Password hashed for user ${phone}`);
      }
    }

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Login gagal. Nomor telepon atau password salah.' });
    }

    // Generate JWT token
    const token = jwt.sign({ phone: user.phone }, process.env.JWT_SECRET || 'payplus_secret_key', { expiresIn: '24h' });

    // Set the token as a cookie
    res.cookie('token', token, {
      httpOnly: true, // Prevents JavaScript access to the cookie
      secure: process.env.NODE_ENV === 'production', // Use secure in production
      sameSite: 'lax', // Helps prevent CSRF
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
    });

    res.status(200).json({
      message: 'Login berhasil',
      phone: user.phone,
      token, // Still include token in response for client-side storage if needed
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

//## LOGOUT
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
        message: 'Semua kolom (phone, name, email, password) harus diisi',
      });
    }

    // Check if user already exists
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);

    if (existingUsers.length > 0) {
      return res.status(400).json({
        message: 'Registrasi gagal. Nomor telepon sudah terdaftar.',
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user with hashed password
    await pool.query('INSERT INTO users (phone, name, email, password, balance) VALUES (?, ?, ?, ?, ?)', [phone, name, email, hashedPassword, 0]);

    res.status(201).json({ message: 'Registrasi berhasil' });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ... existing code ...

// Friends endpoints
// Add friend
app.post('/api/friends', authenticateToken, async (req, res) => {
  try {
    const userPhone = req.user.phone;
    const { friendPhone } = req.body;

    if (!friendPhone) {
      return res.status(400).json({ message: 'Nomor telepon teman diperlukan' });
    }

    // Validasi format nomor telepon
    if (!/^\d+$/.test(friendPhone)) {
      return res.status(400).json({ message: 'Format nomor telepon tidak valid' });
    }

    // Cek apakah nomor telepon teman ada di database
    const [friendExists] = await pool.query('SELECT * FROM users WHERE phone = ?', [friendPhone]);

    if (friendExists.length === 0) {
      return res.status(404).json({ message: 'Pengguna dengan nomor telepon tersebut tidak ditemukan' });
    }

    // Cek apakah mencoba menambahkan diri sendiri
    if (userPhone === friendPhone) {
      return res.status(400).json({ message: 'Anda tidak dapat menambahkan diri sendiri sebagai teman' });
    }

    // Cek apakah pertemanan sudah ada
    const [existingFriendship] = await pool.query('SELECT * FROM friends WHERE (user_phone = ? AND friend_phone = ?) OR (user_phone = ? AND friend_phone = ?)', [userPhone, friendPhone, friendPhone, userPhone]);

    if (existingFriendship.length > 0) {
      const friendship = existingFriendship[0];

      if (friendship.status === 'accepted') {
        return res.status(400).json({ message: 'Pengguna ini sudah menjadi teman Anda' });
      } else if (friendship.status === 'pending') {
        return res.status(400).json({ message: 'Permintaan pertemanan sudah dikirim sebelumnya' });
      } else if (friendship.status === 'rejected') {
        // Jika ditolak sebelumnya, bisa mencoba lagi
        await pool.query('UPDATE friends SET status = "pending", updated_at = NOW() WHERE id = ?', [friendship.id]);
        return res.status(200).json({ message: 'Permintaan pertemanan berhasil dikirim' });
      }
    }

    // Tambahkan pertemanan baru
    await pool.query('INSERT INTO friends (user_phone, friend_phone, status) VALUES (?, ?, "pending")', [userPhone, friendPhone]);

    res.status(201).json({ message: 'Permintaan pertemanan berhasil dikirim' });
  } catch (error) {
    console.error('Add friend error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const userPhone = req.user.phone;

    // Ambil daftar teman yang sudah diterima
    const [friends] = await pool.query(
      `
      SELECT u.phone, u.name, u.email, f.status, f.created_at
      FROM friends f
      JOIN users u ON (f.friend_phone = u.phone)
      WHERE f.user_phone = ? AND f.status = 'accepted'
      UNION
      SELECT u.phone, u.name, u.email, f.status, f.created_at
      FROM friends f
      JOIN users u ON (f.user_phone = u.phone)
      WHERE f.friend_phone = ? AND f.status = 'accepted'
      ORDER BY created_at DESC
    `,
      [userPhone, userPhone]
    );

    res.status(200).json({
      message: 'Daftar teman berhasil diambil',
      friends: friends,
    });
  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

//## API UNTUK GET PROFILE
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { phone } = req.user;

    const [[user]] = await pool.query(
      'SELECT phone, name, email, balance FROM users WHERE phone = ?',
      [phone]
    );

    const [[{ total_income = 0 }]] = await pool.query(
      'SELECT SUM(amount) AS total_income FROM income WHERE phone = ?',
      [phone]
    );

    const [[{ total_expense = 0 }]] = await pool.query(
      'SELECT SUM(amount) AS total_expense FROM expense WHERE phone = ?',
      [phone]
    );

    res.json({
      ...user,
      balance: parseFloat(user.balance),
      total_income: parseFloat(total_income),
      total_expense: parseFloat(total_expense),
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

//## API UNTUK UPDATE PROFILE
app.patch('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, email } = req.body;
    const phone = req.user.phone;

    if (!name || !email) {
      return res.status(400).json({
        message: 'Field name dan email harus diisi untuk update',
      });
    }
    await pool.query(
      'UPDATE users SET name = ?, email = ? WHERE phone = ?',
      [name, email, phone]
    );

    res.json({ message: 'Profil berhasil diperbarui' });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

//## API UNTUK GANTI PASSWORD
app.patch('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const phone = req.user.phone;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        message: 'Password lama dan password baru harus diisi',
      });
    }

    const [users] = await pool.query('SELECT password FROM users WHERE phone = ?', [phone]);

    const user = users[0];
    const isValid = await bcrypt.compare(oldPassword, user.password);
    if (!isValid) {
      return res.status(401).json({ message: 'Password lama tidak valid' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE phone = ?', [hashedPassword, phone]);

    res.json({ message: 'Password berhasil diubah' });
  } catch (error) {
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
        message: 'Kolom nama dan target harus diisi',
      });
    }

    // Insert the new savings record
    const [result] = await pool.query('INSERT INTO savings (phone, nama, deskripsi, target, terkumpul) VALUES (?, ?, ?, ?, ?)', [phone, nama, deskripsi, target, terkumpul]);

    // Get the inserted savings record to return in response
    const [newSavings] = await pool.query('SELECT id, nama, deskripsi, target, terkumpul FROM savings WHERE id = ?', [result.insertId]);

    res.status(201).json({
      success: true,
      message: 'Tabungan berhasil ditambahkan',
      data: {
        id: newSavings[0].id,
        nama: newSavings[0].nama,
        deskripsi: newSavings[0].deskripsi || '',
        target: newSavings[0].target.toString(),
        terkumpul: newSavings[0].terkumpul.toString(),
      },
    });
  } catch (error) {
    console.error('Create savings error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal menambahkan tabungan',
    });
  }
});

app.get('/api/savings/summary', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);

    if (users.length === 0) {
      return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
    }

    // Get savings summary
    const [result] = await pool.query('SELECT SUM(target) as total_target, SUM(terkumpul) as total_terkumpul FROM savings WHERE phone = ?', [phone]);

    if (!result[0].total_target) {
      return res.json({ total_target: 0, total_terkumpul: 0 });
    }

    res.json({
      total_target: parseFloat(result[0].total_target),
      total_terkumpul: parseFloat(result[0].total_terkumpul || 0),
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
    const [summaryResult] = await pool.query(
      `
      SELECT 
        SUM(target) as total_target,
        SUM(terkumpul) as total_terkumpul
      FROM savings 
      WHERE phone = ?
    `,
      [phone]
    );

    // Get all savings records
    const [savingsRecords] = await pool.query(
      `
      SELECT 
        id,
        nama as namaSavings,
        deskripsi,
        target,
        terkumpul
      FROM savings
      WHERE phone = ?
      ORDER BY id ASC
    `,
      [phone]
    );

    // Format the response data
    const summary = {
      total_target: summaryResult[0].total_target ? parseInt(summaryResult[0].total_target).toString() : '0',
      total_terkumpul: summaryResult[0].total_terkumpul ? parseInt(summaryResult[0].total_terkumpul).toString() : '0',
    };

    const formattedRecords = savingsRecords.map((record) => ({
      id: record.id,
      namaSavings: record.namaSavings,
      deskripsi: record.deskripsi || '',
      target: record.target.toString(),
      terkumpul: record.terkumpul.toString(),
    }));

    res.json({
      summary: summary,
      records: formattedRecords,
    });
  } catch (error) {
    console.error('Get savings error:', error);
    res.status(500).json({ message: 'Gagal mengambil data tabungan' });
  }
});

// Update savings accumulated amount
app.patch('/api/savings/:id', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const savingsId = req.params.id;
    const { terkumpul } = req.body;

    // Validate input
    if (terkumpul === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Nilai terkumpul harus diisi',
      });
    }

    // Check if the savings record exists and belongs to the user
    const [savings] = await pool.query('SELECT * FROM savings WHERE id = ? AND phone = ?', [savingsId, phone]);

    if (savings.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Data tabungan tidak ditemukan atau bukan milik Anda',
      });
    }

    // Add the new amount to the existing terkumpul value
    const currentAmount = parseInt(savings[0].terkumpul);
    const additionalAmount = parseInt(terkumpul);
    const newTotalAmount = currentAmount + additionalAmount;

    // Update with the new total
    await pool.query('UPDATE savings SET terkumpul = ? WHERE id = ? AND phone = ?', [newTotalAmount, savingsId, phone]);

    // Get the updated savings record
    const [updatedSavings] = await pool.query('SELECT id, nama, deskripsi, target, terkumpul FROM savings WHERE id = ?', [savingsId]);

    res.json({
      success: true,
      message: 'Tabungan berhasil diperbarui',
      data: {
        id: updatedSavings[0].id,
        nama: updatedSavings[0].nama,
        deskripsi: updatedSavings[0].deskripsi || '',
        target: updatedSavings[0].target.toString(),
        terkumpul: updatedSavings[0].terkumpul.toString(),
      },
    });
  } catch (error) {
    console.error('Update savings error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal memperbarui tabungan',
    });
  }
});

// Delete savings record
app.delete('/api/savings/:id', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const savingsId = req.params.id;

    // Check if the savings record exists and belongs to the user
    const [savings] = await pool.query('SELECT * FROM savings WHERE id = ? AND phone = ?', [savingsId, phone]);

    if (savings.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Data tabungan tidak ditemukan atau bukan milik Anda',
      });
    }

    // Save the data before deletion for response
    const deletedSavings = {
      id: savings[0].id,
      nama: savings[0].nama,
      deskripsi: savings[0].deskripsi || '',
      target: savings[0].target.toString(),
      terkumpul: savings[0].terkumpul.toString(),
    };

    // Delete the savings record
    await pool.query('DELETE FROM savings WHERE id = ? AND phone = ?', [savingsId, phone]);

    res.json({
      success: true,
      message: 'Tabungan berhasil dihapus',
      data: deletedSavings,
    });
  } catch (error) {
    console.error('Delete savings error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal menghapus tabungan',
    });
  }
});

// Bills endpoints
// Create new bill
app.post('/api/bills', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const { name, amount, dueDate, category } = req.body;

    // Validate required fields
    if (!name || !amount || !dueDate || !category) {
      return res.status(400).json({
        success: false,
        message: 'Semua kolom (name, amount, dueDate, category) harus diisi',
      });
    }

    // Insert the new bill
    const [result] = await pool.query('INSERT INTO bill (phone, name, amount, dueDate, category) VALUES (?, ?, ?, ?, ?)', [phone, name, amount, dueDate, category]);

    // Get the inserted bill
    const [newBill] = await pool.query('SELECT id, name, amount, dueDate, category FROM bill WHERE id = ?', [result.insertId]);

    res.status(201).json({
      success: true,
      message: 'Tagihan berhasil ditambahkan',
      data: {
        id: newBill[0].id,
        name: newBill[0].name,
        amount: newBill[0].amount.toString(),
        dueDate: newBill[0].dueDate,
        category: newBill[0].category,
      },
    });
  } catch (error) {
    console.error('Create bill error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal menambahkan tagihan',
    });
  }
});

// Get bills
app.get('/api/bills', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    // Get bills - the table is named 'bill' in the provided schema
    const [bills] = await pool.query('SELECT id, name, amount, dueDate, category FROM bill WHERE phone = ?', [phone]);

    res.json({ bills });
  } catch (error) {
    console.error('Get bills error:', error);
    res.status(500).json({ message: 'Gagal mengambil data tagihan' });
  }
});

// Update bill
app.put('/api/bills/:id', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const billId = req.params.id;
    const { name, amount, dueDate, category } = req.body;

    // Validate required fields
    if (!name || !amount || !dueDate || !category) {
      return res.status(400).json({
        success: false,
        message: 'Semua kolom (name, amount, dueDate, category) harus diisi',
      });
    }

    // Check if the bill exists and belongs to the user
    const [bills] = await pool.query('SELECT * FROM bill WHERE id = ? AND phone = ?', [billId, phone]);

    if (bills.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Data tagihan tidak ditemukan atau bukan milik Anda',
      });
    }

    // Update the bill
    await pool.query('UPDATE bill SET name = ?, amount = ?, dueDate = ?, category = ? WHERE id = ? AND phone = ?', [name, amount, dueDate, category, billId, phone]);

    // Get the updated bill
    const [updatedBill] = await pool.query('SELECT id, name, amount, dueDate, category FROM bill WHERE id = ?', [billId]);

    res.json({
      success: true,
      message: 'Tagihan berhasil diperbarui',
      data: {
        id: updatedBill[0].id,
        name: updatedBill[0].name,
        amount: updatedBill[0].amount.toString(),
        dueDate: updatedBill[0].dueDate,
        category: updatedBill[0].category,
      },
    });
  } catch (error) {
    console.error('Update bill error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal memperbarui tagihan',
    });
  }
});

// Delete bill
app.delete('/api/bills/:id', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const billId = req.params.id;

    // Check if the bill exists and belongs to the user
    const [bills] = await pool.query('SELECT * FROM bill WHERE id = ? AND phone = ?', [billId, phone]);

    if (bills.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Data tagihan tidak ditemukan atau bukan milik Anda',
      });
    }

    // Save the data before deletion for response
    const deletedBill = {
      id: bills[0].id,
      name: bills[0].name,
      amount: bills[0].amount.toString(),
      dueDate: bills[0].dueDate,
      category: bills[0].category,
    };

    // Delete the bill
    await pool.query('DELETE FROM bill WHERE id = ? AND phone = ?', [billId, phone]);

    res.json({
      success: true,
      message: 'Tagihan berhasil dihapus',
      data: deletedBill,
    });
  } catch (error) {
    console.error('Delete bill error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal menghapus tagihan',
    });
  }
});

// Transactions endpoints
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    // Get income from income table
    const [income] = await pool.query('SELECT amount, sender_phone, type, date FROM income WHERE phone = ?', [phone]);

    // Get expenses from expense table
    const [expense] = await pool.query('SELECT amount, receiver_phone, type, date, message FROM expense WHERE phone = ?', [phone]);

    // Format the income data to match the expected format
    const formattedIncome = income.map((item) => ({
      amount: parseFloat(item.amount),
      sender_phone: item.sender_phone.toString(),
      type: item.type,
      date: formatDate(item.date),
    }));

    // Format the expense data to match the expected format
    const formattedExpense = expense.map((item) => ({
      amount: parseFloat(item.amount),
      receiver_phone: item.receiver_phone.toString(),
      type: item.type,
      date: formatDate(item.date),
      message: item.message,
    }));

    res.json({ income: formattedIncome, expense: formattedExpense });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ message: 'Gagal mengambil data transaksi' });
  }
});

//## GET INCOME RECORDS
app.get('/api/income-record', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    // Get income records for the user
    const [incomeRecords] = await pool.query(
      `SELECT 
        i.id, 
        i.amount, 
        i.sender_phone, 
        u.name as sender_name,
        i.type, 
        i.date, 
        i.message
      FROM income i
      LEFT JOIN users u ON i.sender_phone = u.phone
      WHERE i.phone = ?
      ORDER BY i.date DESC`,
      [phone]
    );

    // Format the response data
    const formattedRecords = incomeRecords.map((record) => ({
      id: record.id,
      amount: record.amount ? parseInt(record.amount).toString() : '0',
      sender_phone: record.sender_phone ? record.sender_phone.toString() : '',
      sender_name: record.sender_name || 'Unknown',
      type: record.type || 'normal',
      date: record.date.toLocaleDateString('en-CA'),
      message: record.message || '',
    }));

    res.json({
      success: true,
      message: 'Data pemasukan berhasil diambil',
      records: formattedRecords ??[],
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Add income record
app.post('/api/income-record', authenticateToken, async (req, res) => {
  try {
    const userPhone = req.user.phone;
    const { amount, senderPhone, type, message } = req.body;

    // Validasi input
    if (!amount || !senderPhone || !type) {
      return res.status(400).json({
        message: 'Data tidak lengkap. Amount, senderPhone, dan type diperlukan'
      });
    }

    // Validasi tipe income
    if (!['normal', 'gift', 'topup'].includes(type)) {
      return res.status(400).json({
        message: 'Tipe income tidak valid. Pilih normal, gift, atau topup'
      });
    }

    // Validasi pengirim ada di database
    const [senderExists] = await pool.query('SELECT * FROM users WHERE phone = ?', [senderPhone]);
    if (senderExists.length === 0) {
      return res.status(404).json({
        message: 'Pengirim dengan nomor telepon tersebut tidak ditemukan'
      });
    }

    // Tanggal saat ini
    const currentDate = new Date().toISOString().split('T')[0]; // Format YYYY-MM-DD

    // Tambahkan record income baru
    const [result] = await pool.query(
      'INSERT INTO income (amount, phone, sender_phone, type, date, message) VALUES (?, ?, ?, ?, ?, ?)',
      [amount, userPhone, senderPhone, type, currentDate, message || null]
    );

    // Update saldo pengguna
    await pool.query(
      'UPDATE users SET balance = balance + ? WHERE phone = ?',
      [amount, userPhone]
    );

    res.status(201).json({
      message: 'Income berhasil ditambahkan',
      data: {
        id: result.insertId,
        amount: parseFloat(amount),
        date: currentDate,
        type: type,
        senderPhone: senderPhone.toString(),
        message: message || null
      }
    });
  } catch (error) {
    console.error('Add income record error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Income Record Summary endpoint
app.get('/api/income-record-summary', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    // Get total income
    const [totalResult] = await pool.query('SELECT SUM(amount) as total_income FROM income WHERE phone = ?', [phone]);

    // Get income by type
    const [incomeByType] = await pool.query('SELECT type, SUM(amount) as total FROM income WHERE phone = ? GROUP BY type', [phone]);

    // Get total transactions count
    const [transactionCount] = await pool.query('SELECT COUNT(*) as total_transactions FROM income WHERE phone = ?', [phone]);

    // Format the response
    const totalIncome = totalResult[0].total_income || 0;

    // Initialize with default values
    let normalIncome = 0;
    let giftIncome = 0;
    let topupIncome = 0;

    // Map the income by type
    incomeByType.forEach((item) => {
      switch (item.type) {
        case 'normal':
          normalIncome = parseFloat(item.total);
          break;
        case 'gift':
          giftIncome = parseFloat(item.total);
          break;
        case 'topup':
          topupIncome = parseFloat(item.total);
          break;
      }
    });

    res.json({
      success: true,
      data: {
        total_income: totalIncome.toString(),
        normal_income: normalIncome.toString(),
        gift_income: giftIncome.toString(),
        topup_income: topupIncome.toString(),
        total_transactions: transactionCount[0].total_transactions,
      },
    });
  } catch (error) {
    console.error('Get income record summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal mengambil data ringkasan pendapatan',
    });
  }
});

// Expense record endpoint
app.get('/api/expense-record', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    // Join expense table with users table to get receiver names
    const [expenseRecords] = await pool.query(
      `
      SELECT 
        e.amount, 
        e.receiver_phone, 
        u.name AS receiver, 
        e.type, 
        e.date, 
        e.message
      FROM expense e
      LEFT JOIN users u ON e.receiver_phone = u.phone
      WHERE e.phone = ?
      ORDER BY e.date DESC
    `,
      [phone]
    );

    // Get summary statistics
    const [summaryResults] = await pool.query(
      `
      SELECT 
        SUM(amount) as total_expense,
        COUNT(*) as total_transactions,
        SUM(CASE WHEN type = 'normal' THEN amount ELSE 0 END) as total_normal,
        SUM(CASE WHEN type = 'gift' THEN amount ELSE 0 END) as total_gift,
        COUNT(CASE WHEN type = 'normal' THEN 1 END) as count_normal,
        COUNT(CASE WHEN type = 'gift' THEN 1 END) as count_gift
      FROM expense
      WHERE phone = ?
    `,
      [phone]
    );

    const summary = {
      total_expense: summaryResults[0].total_expense ? parseInt(summaryResults[0].total_expense).toString() : '0',
      total_transactions: summaryResults[0].total_transactions,
      total_normal: summaryResults[0].total_normal ? parseInt(summaryResults[0].total_normal).toString() : '0',
      total_gift: summaryResults[0].total_gift ? parseInt(summaryResults[0].total_gift).toString() : '0',
      count_normal: summaryResults[0].count_normal || 0,
      count_gift: summaryResults[0].count_gift || 0,
    };

    // Format the response data
    const formattedRecords = expenseRecords.map((record) => ({
      amount: record.amount.toString(),
      receiver: record.receiver || 'Unknown', // Handle case where receiver might not be in users table
      type: record.type,
      message: record.message || '',
    }));

    res.json({
      summary: summary,
      records: formattedRecords,
    });
  } catch (error) {
    console.error('Get expense records error:', error);
    res.status(500).json({ message: 'Gagal mengambil data riwayat pengeluaran' });
  }
});

// Add expense record
app.post('/api/expense-record', authenticateToken, async (req, res) => {
  try {
    const userPhone = req.user.phone;
    const { amount, receiverPhone, type, message } = req.body;

    // Validasi input
    if (!amount || !receiverPhone || !type) {
      return res.status(400).json({
        message: 'Jumlah, nomor telepon penerima, dan tipe transaksi diperlukan'
      });
    }

    // Validasi tipe transaksi
    if (!['normal', 'gift'].includes(type)) {
      return res.status(400).json({
        message: 'Tipe transaksi harus berupa "normal" atau "gift"'
      });
    }

    // Validasi jumlah harus positif
    if (amount <= 0) {
      return res.status(400).json({
        message: 'Jumlah harus lebih dari 0'
      });
    }

    // Cek apakah penerima ada di database
    const [receiverExists] = await pool.query('SELECT * FROM users WHERE phone = ?', [receiverPhone]);

    if (receiverExists.length === 0) {
      return res.status(404).json({
        message: 'Penerima dengan nomor telepon tersebut tidak ditemukan'
      });
    }

    // Cek saldo pengirim
    const [senderData] = await pool.query('SELECT balance FROM users WHERE phone = ?', [userPhone]);
    
    if (senderData[0].balance < amount) {
      return res.status(400).json({
        message: 'Saldo tidak mencukupi untuk melakukan transaksi ini'
      });
    }

    // Mulai transaksi database
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Tanggal saat ini untuk transaksi
      const currentDate = new Date().toISOString().split('T')[0]; // Format YYYY-MM-DD

      // Catat pengeluaran (expense)
      const [expenseResult] = await connection.query(
        'INSERT INTO expense (amount, phone, receiver_phone, type, date, message) VALUES (?, ?, ?, ?, ?, ?)',
        [amount, userPhone, receiverPhone, type, currentDate, message || null]
      );

      // Catat pemasukan (income) untuk penerima
      await connection.query(
        'INSERT INTO income (amount, phone, sender_phone, type, date, message) VALUES (?, ?, ?, ?, ?, ?)',
        [amount, receiverPhone, userPhone, type, currentDate, message || null]
      );

      // Update saldo pengirim (kurangi)
      await connection.query(
        'UPDATE users SET balance = balance - ? WHERE phone = ?',
        [amount, userPhone]
      );

      // Update saldo penerima (tambah)
      await connection.query(
        'UPDATE users SET balance = balance + ? WHERE phone = ?',
        [amount, receiverPhone]
      );

      // Commit transaksi
      await connection.commit();

      // Ambil data penerima untuk response
      const [receiverData] = await pool.query('SELECT name FROM users WHERE phone = ?', [receiverPhone]);

      res.status(201).json({
        message: 'Transaksi berhasil',
        data: {
          id: expenseResult.insertId,
          amount: amount,
          date: currentDate,
          type: type,
          receiver_phone: receiverPhone,
          message: message || null
        }
      });
    } catch (error) {
      // Rollback jika terjadi error
      await connection.rollback();
      throw error;
    } finally {
      // Lepaskan koneksi
      connection.release();
    }
  } catch (error) {
    console.error('Expense record error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Search user by phone number endpoint
app.get('/api/search-user/:phone', authenticateToken, async (req, res) => {
  try {
    const searchPhone = req.params.phone;

    // Search for the exact phone number
    const [users] = await pool.query('SELECT phone, name FROM users WHERE phone = ?', [searchPhone]);

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User tidak ditemukan',
      });
    }

    res.json({
      success: true,
      data: {
        phone: users[0].phone.toString(),
        name: users[0].name,
      },
    });
  } catch (error) {
    console.error('Search user error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal mencari user',
    });
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
    tokenCookie: req.cookies.token,
  });
});

// Upcoming bills endpoint
app.get('/api/upcoming-bills', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    // Get upcoming bills
    // Convert string dates to proper date objects for comparison
    const [billsRecords] = await pool.query(
      `
      SELECT 
        id,
        name as nameBills,
        amount,
        dueDate,
        category
      FROM bill
      WHERE phone = ?
      ORDER BY STR_TO_DATE(dueDate, '%Y-%m-%d') ASC
    `,
      [phone]
    );

    // Format the response data
    const formattedBills = billsRecords.map((bill) => ({
      nameBills: bill.nameBills,
      amount: bill.amount.toString(),
      dueDate: bill.dueDate,
      category: bill.category,
    }));

    res.json(formattedBills);
  } catch (error) {
    console.error('Get upcoming bills error:', error);
    res.status(500).json({ message: 'Gagal mengambil data tagihan' });
  }
});

// Helper function to format date
function formatDate(date) {
  if (!date) return null;
  const d = new Date(date);
  return d.toISOString().split('T')[0]; // Format as YYYY-MM-DD
}

// Transfer endpoint
app.post('/api/transfer', authenticateToken, async (req, res) => {
  try {
    const senderPhone = req.user.phone;
    const { receiverPhone, amount, message, type = 'normal' } = req.body;

    // Validate required fields
    if (!receiverPhone || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Nomor penerima dan jumlah transfer harus diisi',
      });
    }

    // Validate amount is a positive number
    const transferAmount = parseInt(amount);
    if (isNaN(transferAmount) || transferAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Jumlah transfer harus berupa angka positif',
      });
    }

    // Check if sender exists and has sufficient balance
    const [senders] = await pool.query('SELECT * FROM users WHERE phone = ?', [senderPhone]);

    if (senders.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Pengguna pengirim tidak ditemukan',
      });
    }

    const sender = senders[0];
    const senderBalance = parseInt(sender.balance);

    if (senderBalance < transferAmount) {
      return res.status(400).json({
        success: false,
        message: 'Saldo tidak mencukupi untuk melakukan transfer',
      });
    }

    // Check if receiver exists
    const [receivers] = await pool.query('SELECT * FROM users WHERE phone = ?', [receiverPhone]);

    if (receivers.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Pengguna penerima tidak ditemukan',
      });
    }

    const receiver = receivers[0];
    const receiverBalance = parseInt(receiver.balance);

    // Begin transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Update sender's balance
      await connection.query('UPDATE users SET balance = ? WHERE phone = ?', [senderBalance - transferAmount, senderPhone]);

      // Update receiver's balance
      await connection.query('UPDATE users SET balance = ? WHERE phone = ?', [receiverBalance + transferAmount, receiverPhone]);

      // Create expense record for sender
      const currentDate = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD
      await connection.query('INSERT INTO expense (amount, phone, receiver_phone, type, date, message) VALUES (?, ?, ?, ?, ?, ?)', [transferAmount, senderPhone, receiverPhone, type, currentDate, message]);

      // Create income record for receiver
      await connection.query('INSERT INTO income (amount, phone, sender_phone, type, date, message) VALUES (?, ?, ?, ?, ?, ?)', [transferAmount, receiverPhone, senderPhone, type, currentDate, message]);

      // Commit transaction
      await connection.commit();

      // Get updated sender balance
      const [updatedSender] = await pool.query('SELECT balance FROM users WHERE phone = ?', [senderPhone]);

      res.json({
        success: true,
        message: 'Transfer berhasil',
        data: {
          transferAmount: transferAmount.toString(),
          receiverPhone: receiverPhone.toString(),
          receiverName: receiver.name,
          date: currentDate,
          remainingBalance: updatedSender[0].balance.toString(),
          type: type,
        },
      });
    } catch (error) {
      // Rollback in case of error
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal melakukan transfer',
    });
  }
});

// Topup endpoint
app.post('/api/topup', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;
    const { amount } = req.body;

    // Validate required fields
    if (!amount) {
      return res.status(400).json({
        success: false,
        message: 'Jumlah topup harus diisi',
      });
    }

    // Validate amount is a positive number
    const topupAmount = parseInt(amount);
    if (isNaN(topupAmount) || topupAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Jumlah topup harus berupa angka positif',
      });
    }

    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Pengguna tidak ditemukan',
      });
    }

    const user = users[0];
    const currentBalance = parseInt(user.balance);
    const newBalance = currentBalance + topupAmount;

    // Begin transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Update user's balance
      await connection.query('UPDATE users SET balance = ? WHERE phone = ?', [newBalance, phone]);

      // Create income record for topup
      const currentDate = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD
      await connection.query('INSERT INTO income (amount, phone, sender_phone, type, date, message) VALUES (?, ?, ?, ?, ?, ?)', [topupAmount, phone, phone, 'topup', currentDate, 'Top up saldo']);

      // Commit transaction
      await connection.commit();

      res.json({
        success: true,
        message: 'Top up berhasil',
        data: {
          topupAmount: topupAmount.toString(),
          newBalance: newBalance.toString(),
          date: currentDate,
        },
      });
    } catch (error) {
      // Rollback in case of error
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Topup error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal melakukan top up',
    });
  }
});

//## RECENT TRANSACTIONS
app.get('/api/recent-transactions', authenticateToken, async (req, res) => {
  try {
    const phone = req.user.phone;

    const [incomeRecords] = await pool.query(
      `
      SELECT 
        i.id,
        i.amount, 
        i.type, 
        i.date, 
        'income' AS transaction_type
      FROM income i
      WHERE i.phone = ?
      ORDER BY i.date DESC, i.id DESC
      LIMIT 5
    `,
      [phone]
    );

    const [expenseRecords] = await pool.query(
      `
      SELECT 
        e.id,
        e.amount, 
        e.type, 
        e.date, 
        'expense' AS transaction_type
      FROM expense e
      WHERE e.phone = ?
      ORDER BY e.date DESC, e.id DESC
      LIMIT 5
    `,
      [phone]
    );

    const formatRecord = (record) => ({
      amount: record.amount.toString(),
      type: record.type,
      date: record.date.toLocaleDateString('en-CA'),
      transactionType: record.transaction_type,
    });

    const allTransactions = [...incomeRecords, ...expenseRecords]
      .sort((a, b) => {
        const dateCompare = new Date(b.date) - new Date(a.date);
        return dateCompare !== 0 ? dateCompare : b.id - a.id;
      })
      .slice(0, 5)
      .map(formatRecord);

    res.json({
      success: true,
      records: allTransactions,
    });
  } catch (error) {
    console.error('Recent transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal mengambil data transaksi terbaru',
    });
  }
});


// Initialize database and start server
initializeDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize server:', err);
  });
