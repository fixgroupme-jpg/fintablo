const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { stmts, saveAllData } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ft5-mvp-secret-change-in-prod';
const TOKEN_EXPIRY = '30d';

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Serve frontend
app.use(express.static(__dirname));

// ========== AUTH MIDDLEWARE ==========
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.userId;
    req.userRole = payload.role;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function ownerOnly(req, res, next) {
  if (req.userRole !== 'owner') return res.status(403).json({ error: 'Owner only' });
  next();
}

function signToken(user) {
  return jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}

// ========== AUTH ROUTES ==========

app.post('/api/auth/register', (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 4) return res.status(400).json({ error: 'Password too short' });

    const existing = stmts.getUserByEmail.get(email);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const allUsers = stmts.listUsers.all();
    const role = allUsers.length === 0 ? 'owner' : 'tester';

    const hash = bcrypt.hashSync(password, 10);
    const result = stmts.createUser.run(email, hash, name || '', role);
    const user = stmts.getUserById.get(result.lastInsertRowid);

    saveAllData(user.id, {
      DB: { ops: [], bal: 0 },
      REF: { incCats: [], svcs: [], expCats: [], expTypes: [] },
      cpMap: {},
      rules: [],
      FP: { assets: [], liabilities: [], openBal: [], clientObl: [], accounts: [] }
    });

    const token = signToken(user);
    res.json({ token, user });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = stmts.getUserByEmail.get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken(user);
    const { password_hash, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = stmts.getUserById.get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

// ========== DATA ROUTES ==========

app.get('/api/data', auth, (req, res) => {
  try {
    const rows = stmts.getData.all(req.userId);
    const data = {};
    for (const row of rows) {
      try { data[row.key] = JSON.parse(row.value); } catch { data[row.key] = row.value; }
    }
    res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/data', auth, (req, res) => {
  try {
    const { data } = req.body;
    if (!data || typeof data !== 'object') return res.status(400).json({ error: 'data object required' });
    saveAllData(req.userId, data);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/data/:key', auth, (req, res) => {
  try {
    const { key } = req.params;
    const { value } = req.body;
    if (value === undefined) return res.status(400).json({ error: 'value required' });
    stmts.upsertData.run(req.userId, key, JSON.stringify(value));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== ADMIN ROUTES ==========

app.get('/api/admin/users', auth, ownerOnly, (req, res) => {
  const users = stmts.listUsers.all();
  res.json({ users });
});

app.post('/api/admin/users', auth, ownerOnly, (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const existing = stmts.getUserByEmail.get(email);
    if (existing) return res.status(409).json({ error: 'Email exists' });

    const hash = bcrypt.hashSync(password, 10);
    const result = stmts.createUser.run(email, hash, name || '', role || 'tester');
    const user = stmts.getUserById.get(result.lastInsertRowid);

    saveAllData(user.id, {
      DB: { ops: [], bal: 0 },
      REF: { incCats: [], svcs: [], expCats: [], expTypes: [] },
      cpMap: {},
      rules: [],
      FP: { assets: [], liabilities: [], openBal: [], clientObl: [], accounts: [] }
    });

    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/admin/users/:id', auth, ownerOnly, (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
  stmts.deleteUser.run(id);
  res.json({ ok: true });
});

// ========== BACKUP ROUTES ==========

app.get('/api/backup', auth, (req, res) => {
  const rows = stmts.getData.all(req.userId);
  const data = {};
  for (const row of rows) {
    try { data[row.key] = JSON.parse(row.value); } catch { data[row.key] = row.value; }
  }
  const user = stmts.getUserById.get(req.userId);
  res.json({ version: 'ft5-server', exportedAt: new Date().toISOString(), user: { email: user.email, name: user.name }, ...data });
});

app.post('/api/backup', auth, (req, res) => {
  try {
    const { DB, REF, cpMap, rules, FP } = req.body;
    if (!DB || !REF) return res.status(400).json({ error: 'Invalid backup' });
    saveAllData(req.userId, { DB, REF, cpMap: cpMap || {}, rules: rules || [], FP: FP || { assets: [], liabilities: [], openBal: [], clientObl: [], accounts: [] } });
    res.json({ ok: true, ops: DB.ops?.length || 0 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== FALLBACK ==========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'v6.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  ╔══════════════════════════════════════╗`);
  console.log(`  ║  Финтабло MVP — http://localhost:${PORT}  ║`);
  console.log(`  ╚══════════════════════════════════════╝\n`);
  console.log(`  First registered user becomes owner.\n`);
});
