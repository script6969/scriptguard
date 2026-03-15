const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { nanoid } = require('nanoid');
const db      = require('../db');
const { requireAuth, JWT_SECRET } = require('../middleware/auth');

// POST /api/auth/register
router.post('/register', (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password)
    return res.status(400).json({ error: 'All fields are required' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
  if (existing) return res.status(409).json({ error: 'Email or username already taken' });

  const hash   = bcrypt.hashSync(password, 10);
  const apiKey = 'sg_' + nanoid(32);

  const stmt = db.prepare(
    'INSERT INTO users (email, username, password, api_key) VALUES (?, ?, ?, ?)'
  );
  const result = stmt.run(email.toLowerCase().trim(), username.trim(), hash, apiKey);

  const user  = db.prepare('SELECT id, email, username, plan, api_key, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });

  res.status(201).json({ token, user });
});

// POST /api/auth/login
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  const safe  = { id: user.id, email: user.email, username: user.username, plan: user.plan, api_key: user.api_key, created_at: user.created_at };

  res.json({ token, user: safe });
});

// GET /api/auth/me
router.get('/me', requireAuth, (req, res) => {
  const { id, email, username, plan, api_key, created_at } = req.user;
  res.json({ id, email, username, plan, api_key, created_at });
});

// POST /api/auth/regenerate-key
router.post('/regenerate-key', requireAuth, (req, res) => {
  const newKey = 'sg_' + nanoid(32);
  db.prepare('UPDATE users SET api_key = ? WHERE id = ?').run(newKey, req.user.id);
  res.json({ api_key: newKey });
});

module.exports = router;
