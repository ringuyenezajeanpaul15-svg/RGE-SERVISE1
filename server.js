require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_FILE = path.join(__dirname, 'database.json');

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], otp_codes: {}, service_requests: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
  }
  const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!data.users) data.users = [];
  if (!data.otp_codes) data.otp_codes = {};
  if (!data.service_requests) data.service_requests = {};
  if (!Array.isArray(data.service_requests)) data.service_requests = [];
  return data;
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. Please login.' });

  const secret = process.env.JWT_SECRET || 'RGE_LOCAL_SECRET_2026';
  jwt.verify(token, secret, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired. Login again.' });
    req.user = user;
    next();
  });
}

// 1A. GENERATE FREE 6-DIGIT VERIFICATION CODE (0 RWF Prototype Mode)
app.post('/api/send-otp', (req, res) => {
  try {
    const { phone } = req.body;
    const cleanPhone = (phone || '').trim();

    if (!/^07[2389]\d{7}$/.test(cleanPhone)) {
      return res.status(400).json({ error: 'Enter a valid 10-digit Rwandan number (e.g., 078XXXXXXX).' });
    }

    const db = readDB();
    if (db.users.some(u => u.phone === cleanPhone)) {
      return res.status(400).json({ error: 'This phone number is already registered.' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    db.otp_codes[cleanPhone] = { code, expiresAt: Date.now() + 10 * 60000 };
    writeDB(db);

    console.log(`\n========================================`);
    console.log(`📲 FREE OTP FOR ${cleanPhone}: [ ${code} ]`);
    console.log(`========================================\n`);

    res.json({
      success: true,
      demo_code: code,
      message: 'Verification code generated!'
    });
  } catch (err) {
    console.error('OTP error:', err);
    res.status(500).json({ error: 'Server error generating verification code.' });
  }
});

// 1B. VERIFY CODE & CREATE ACCOUNT
app.post('/api/register', async (req, res) => {
  try {
    const { role, full_name, phone, password, otp, photo_url, province, district, location_desc, skill_level, languages } = req.body;
    const cleanPhone = (phone || '').trim();

    if (!full_name || !cleanPhone || !password) {
      return res.status(400).json({ error: 'Please fill in all required fields.' });
    }

    if (password.length !== 8) {
      return res.status(400).json({ error: 'Password must be exactly 8 characters/digits.' });
    }

    const db = readDB();
    const record = db.otp_codes[cleanPhone];

    if (!record || record.code !== (otp || '').trim()) {
      return res.status(400).json({ error: 'Invalid verification code.' });
    }
    if (Date.now() > record.expiresAt) {
      return res.status(400).json({ error: 'Verification code expired. Request a new one.' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const newUser = {
      id: Date.now(),
      role: role || 'customer',
      full_name: full_name.trim(),
      phone: cleanPhone,
      password_hash,
      photo_url: photo_url || '',
      province: province || null,
      district: district || null,
      location_desc: location_desc || null,
      skill_level: skill_level || null,
      languages: languages || [],
      created_at: new Date().toISOString()
    };

    db.users.push(newUser);
    delete db.otp_codes[cleanPhone];
    writeDB(db);

    const secret = process.env.JWT_SECRET || 'RGE_LOCAL_SECRET_2026';
    const token = jwt.sign({ id: newUser.id, role: newUser.role }, secret, { expiresIn: '7d' });

    res.json({
      success: true,
      token,
      user: { id: newUser.id, role: newUser.role, full_name: newUser.full_name, phone: newUser.phone }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error while creating account.' });
  }
});

// 2. LOGIN (Customers, Technicians & Owner Admin)
app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const cleanPhone = (phone || '').trim();
    const cleanPass = (password || '').trim();

    const adminPhone = (process.env.ADMIN_PHONE || '0785948517').trim();
    const adminPass = (process.env.ADMIN_PASS || '88990011').trim();
    const secret = process.env.JWT_SECRET || 'RGE_LOCAL_SECRET_2026';

    if (cleanPhone === adminPhone && cleanPass === adminPass) {
      const token = jwt.sign({ id: 0, role: 'admin' }, secret, { expiresIn: '7d' });
      return res.json({
        success: true,
        token,
        user: { role: 'admin', full_name: 'RGE Owner Admin', phone: adminPhone }
      });
    }

    const db = readDB();
    const user = db.users.find(u => u.phone === cleanPhone);
    if (!user) return res.status(400).json({ error: 'Account not found.' });

    const validPass = await bcrypt.compare(password, user.password_hash);
    if (!validPass) return res.status(400).json({ error: 'Incorrect 8-digit password.' });

    const token = jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: '7d' });
    res.json({
      success: true,
      token,
      user: { id: user.id, role: user.role, full_name: user.full_name, phone: user.phone }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// 3. PUBLIC STATS
app.get('/api/stats', (req, res) => {
  const db = readDB();
  res.json({
    customers: db.users.filter(u => u.role === 'customer').length,
    technicians: db.users.filter(u => u.role === 'technician').length
  });
});

// 4. PRIVACY-PROTECTED DIRECTORY (Only Name & Photo returned)
app.get('/api/directory/:role', authenticateToken, (req, res) => {
  const { role } = req.params;
  if (!['customer', 'technician'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

  const db = readDB();
  const safeList = db.users
    .filter(u => u.role === role)
    .map(u => ({ id: u.id, full_name: u.full_name, photo_url: u.photo_url }));

  res.json(safeList);
});

// 5. SAVE SERVICE APPLICATION
app.post('/api/apply-service', (req, res) => {
  const db = readDB();
  db.service_requests.unshift({ id: Date.now(), ...req.body, created_at: new Date().toISOString() });
  writeDB(db);
  res.json({ success: true });
});

// 6. OWNER ADMIN FULL DISPATCH DATA
app.get('/api/admin/all-data', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Owner access only.' });
  }
  const db = readDB();
  res.json({
    technicians: db.users.filter(u => u.role === 'technician'),
    customers: db.users.filter(u => u.role === 'customer'),
    requests: db.service_requests
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`RGE Services Server running at http://localhost:${PORT}`));