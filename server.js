const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { nanoid } = require('nanoid');
const path      = require('path');
const { DatabaseSync } = require('node:sqlite');

const app    = express();
const PORT   = 3000;
const SECRET = 'scriptguard-secret-key';

// ---- DATABASE ----
const db = new DatabaseSync(path.join(__dirname, 'data.db'));
db.exec(`PRAGMA journal_mode = WAL`);
db.exec(`PRAGMA foreign_keys = ON`);
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    plan       TEXT NOT NULL DEFAULT 'free',
    api_key    TEXT UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS scripts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS license_keys (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id      INTEGER NOT NULL,
    user_id        INTEGER NOT NULL,
    key            TEXT UNIQUE NOT NULL,
    label          TEXT,
    expires_at     INTEGER,
    max_executions INTEGER,
    executions     INTEGER NOT NULL DEFAULT 0,
    hwid           TEXT,
    ip_lock        TEXT,
    status         TEXT NOT NULL DEFAULT 'active',
    created_at     INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS executions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id     INTEGER NOT NULL,
    script_id  INTEGER NOT NULL,
    hwid       TEXT,
    ip         TEXT,
    success    INTEGER NOT NULL DEFAULT 1,
    reason     TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    type       TEXT NOT NULL,
    value      TEXT NOT NULL,
    reason     TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(user_id, type, value)
  );
`);

// ---- MIDDLEWARE ----
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, SECRET);
    const user    = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function genKey() {
  const s = () => nanoid(6).toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,6).padEnd(6,'0');
  return `SG-${s()}-${s()}-${s()}-${s()}`;
}

// ---- AUTH ----
app.post('/api/auth/register', (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password min 8 characters' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
  if (existing) return res.status(409).json({ error: 'Email or username already taken' });
  const hash   = bcrypt.hashSync(password, 10);
  const apiKey = 'sg_' + nanoid(32);
  const result = db.prepare('INSERT INTO users (email, username, password, api_key) VALUES (?,?,?,?)').run(email.toLowerCase().trim(), username.trim(), hash, apiKey);
  const user   = db.prepare('SELECT id,email,username,plan,api_key,created_at FROM users WHERE id=?').get(result.lastInsertRowid);
  const token  = jwt.sign({ id: user.id }, SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email, username: user.username, plan: user.plan, api_key: user.api_key } });
});

app.get('/api/auth/me', auth, (req, res) => {
  const { id, email, username, plan, api_key, created_at } = req.user;
  res.json({ id, email, username, plan, api_key, created_at });
});

app.post('/api/auth/regenerate-key', auth, (req, res) => {
  const newKey = 'sg_' + nanoid(32);
  db.prepare('UPDATE users SET api_key=? WHERE id=?').run(newKey, req.user.id);
  res.json({ api_key: newKey });
});

// ---- SCRIPTS ----
const PLAN_LIMITS = { free: 1, pro: 10, enterprise: 99999 };

app.get('/api/scripts', auth, (req, res) => {
  const scripts = db.prepare(`
    SELECT s.*,
      COUNT(DISTINCT k.id) AS total_keys,
      COUNT(DISTINCT CASE WHEN k.status='active' THEN k.id END) AS active_keys,
      COUNT(DISTINCT e.id) AS total_executions,
      COUNT(DISTINCT CASE WHEN e.created_at > unixepoch()-86400 THEN e.id END) AS executions_today
    FROM scripts s
    LEFT JOIN license_keys k ON k.script_id=s.id
    LEFT JOIN executions e ON e.script_id=s.id
    WHERE s.user_id=?
    GROUP BY s.id ORDER BY s.created_at DESC
  `).all(req.user.id);
  res.json(scripts);
});

app.post('/api/scripts', auth, (req, res) => {
  const limit   = PLAN_LIMITS[req.user.plan] || 1;
  const current = db.prepare('SELECT COUNT(*) AS n FROM scripts WHERE user_id=?').get(req.user.id).n;
  if (current >= limit) return res.status(403).json({ error: `Your ${req.user.plan} plan allows ${limit} script(s).` });
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const result = db.prepare('INSERT INTO scripts (user_id,name,description) VALUES (?,?,?)').run(req.user.id, name.trim(), (description||'').trim());
  res.status(201).json(db.prepare('SELECT * FROM scripts WHERE id=?').get(result.lastInsertRowid));
});

app.patch('/api/scripts/:id', auth, (req, res) => {
  const s = db.prepare('SELECT * FROM scripts WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  const { name, description, status } = req.body;
  const u = []; const p = [];
  if (name)                    { u.push('name=?');        p.push(name); }
  if (description !== undefined){ u.push('description=?'); p.push(description); }
  if (status)                  { u.push('status=?');      p.push(status); }
  if (!u.length) return res.status(400).json({ error: 'Nothing to update' });
  p.push(req.params.id, req.user.id);
  db.prepare(`UPDATE scripts SET ${u.join(',')} WHERE id=? AND user_id=?`).run(...p);
  res.json(db.prepare('SELECT * FROM scripts WHERE id=?').get(req.params.id));
});

app.delete('/api/scripts/:id', auth, (req, res) => {
  const s = db.prepare('SELECT * FROM scripts WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM scripts WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ---- KEYS ----
app.get('/api/keys', auth, (req, res) => {
  const { script_id, status, page=1, limit=50 } = req.query;
  let where = 'k.user_id=?'; const args = [req.user.id];
  if (script_id) { where += ' AND k.script_id=?'; args.push(script_id); }
  if (status)    { where += ' AND k.status=?';    args.push(status); }
  const keys  = db.prepare(`SELECT k.*,s.name AS script_name FROM license_keys k JOIN scripts s ON s.id=k.script_id WHERE ${where} ORDER BY k.created_at DESC LIMIT ? OFFSET ?`).all(...args, +limit, (+page-1)*+limit);
  const total = db.prepare(`SELECT COUNT(*) AS n FROM license_keys k WHERE ${where}`).get(...args).n;
  res.json({ keys, total });
});

app.post('/api/keys', auth, (req, res) => {
  const { script_id, label, expires_at, max_executions, count=1 } = req.body;
  if (!script_id) return res.status(400).json({ error: 'script_id required' });
  const s = db.prepare('SELECT id FROM scripts WHERE id=? AND user_id=?').get(script_id, req.user.id);
  if (!s) return res.status(403).json({ error: 'Script not found' });
  const qty = Math.min(Math.max(1, +count), 500);
  const insert = db.prepare('INSERT INTO license_keys (script_id,user_id,key,label,expires_at,max_executions) VALUES (?,?,?,?,?,?)');
  const created = [];
  const run = db.transaction(() => {
    for (let i = 0; i < qty; i++) {
      const r = insert.run(script_id, req.user.id, genKey(), label||null, expires_at ? Math.floor(new Date(expires_at).getTime()/1000) : null, max_executions||null);
      created.push(db.prepare('SELECT * FROM license_keys WHERE id=?').get(r.lastInsertRowid));
    }
  });
  run();
  res.status(201).json(qty === 1 ? created[0] : created);
});

app.patch('/api/keys/:id', auth, (req, res) => {
  const k = db.prepare('SELECT * FROM license_keys WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!k) return res.status(404).json({ error: 'Not found' });
  const { status, hwid } = req.body;
  const u = []; const p = [];
  if (status !== undefined) { u.push('status=?'); p.push(status); }
  if (hwid !== undefined)   { u.push('hwid=?');   p.push(hwid); }
  if (!u.length) return res.status(400).json({ error: 'Nothing to update' });
  p.push(req.params.id, req.user.id);
  db.prepare(`UPDATE license_keys SET ${u.join(',')} WHERE id=? AND user_id=?`).run(...p);
  res.json(db.prepare('SELECT * FROM license_keys WHERE id=?').get(req.params.id));
});

app.delete('/api/keys/:id', auth, (req, res) => {
  const k = db.prepare('SELECT * FROM license_keys WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!k) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM license_keys WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ---- VERIFY (public) ----
app.post('/api/keys/verify', (req, res) => {
  const { key, hwid, script_id } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (!key || !script_id) return res.json({ valid: false, reason: 'key and script_id required' });

  const record = db.prepare('SELECT * FROM license_keys WHERE key=? AND script_id=?').get(key, script_id);

  function deny(reason) {
    if (record) db.prepare('INSERT INTO executions (key_id,script_id,hwid,ip,success,reason) VALUES (?,?,?,?,0,?)').run(record.id, script_id, hwid||null, ip, reason);
    return res.json({ valid: false, reason });
  }

  if (!record)                    return deny('Key not found');
  if (record.status !== 'active') return deny('Key is ' + record.status);
  if (record.expires_at && record.expires_at < Math.floor(Date.now()/1000)) return deny('Key expired');
  if (record.max_executions && record.executions >= record.max_executions)  return deny('Execution limit reached');
  if (record.hwid && hwid && record.hwid !== hwid) return deny('HWID mismatch');
  if (!record.hwid && hwid) db.prepare('UPDATE license_keys SET hwid=? WHERE id=?').run(hwid, record.id);

  const blocked = hwid ? db.prepare("SELECT id FROM blacklist WHERE user_id=(SELECT user_id FROM scripts WHERE id=?) AND type='hwid' AND value=?").get(script_id, hwid) : null;
  if (blocked) return deny('Blacklisted');

  db.prepare('UPDATE license_keys SET executions=executions+1 WHERE id=?').run(record.id);
  db.prepare('INSERT INTO executions (key_id,script_id,hwid,ip,success) VALUES (?,?,?,?,1)').run(record.id, script_id, hwid||null, ip);
  res.json({ valid: true, expires_at: record.expires_at, executions: record.executions + 1 });
});

// ---- STATS ----
app.get('/api/stats/overview', auth, (req, res) => {
  const uid = req.user.id;
  const day = Math.floor(Date.now()/1000) - 86400;
  res.json({
    scripts:      db.prepare('SELECT COUNT(*) AS n FROM scripts WHERE user_id=?').get(uid).n,
    totalKeys:    db.prepare('SELECT COUNT(*) AS n FROM license_keys WHERE user_id=?').get(uid).n,
    activeKeys:   db.prepare("SELECT COUNT(*) AS n FROM license_keys WHERE user_id=? AND status='active'").get(uid).n,
    execsToday:   db.prepare('SELECT COUNT(*) AS n FROM executions e JOIN license_keys k ON k.id=e.key_id WHERE k.user_id=? AND e.created_at>?').get(uid, day).n,
    blockedToday: db.prepare('SELECT COUNT(*) AS n FROM executions e JOIN license_keys k ON k.id=e.key_id WHERE k.user_id=? AND e.success=0 AND e.created_at>?').get(uid, day).n,
  });
});

app.get('/api/stats/executions', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT e.*,k.key,s.name AS script_name FROM executions e
    JOIN license_keys k ON k.id=e.key_id
    JOIN scripts s ON s.id=e.script_id
    WHERE k.user_id=? ORDER BY e.created_at DESC LIMIT 100
  `).all(req.user.id);
  res.json(rows);
});

// ---- BLACKLIST ----
app.get('/api/blacklist', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM blacklist WHERE user_id=? ORDER BY created_at DESC').all(req.user.id));
});

app.post('/api/blacklist', auth, (req, res) => {
  const { type, value, reason } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'type and value required' });
  try {
    const r = db.prepare('INSERT INTO blacklist (user_id,type,value,reason) VALUES (?,?,?,?)').run(req.user.id, type, value.trim(), reason||null);
    res.status(201).json(db.prepare('SELECT * FROM blacklist WHERE id=?').get(r.lastInsertRowid));
  } catch { res.status(409).json({ error: 'Already blacklisted' }); }
});

app.delete('/api/blacklist/:id', auth, (req, res) => {
  const r = db.prepare('SELECT * FROM blacklist WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM blacklist WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ---- HEALTH & SPA ----
app.get('/api/health', (_, res) => res.json({ ok: true }));
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

app.listen(PORT, () => console.log(`ScriptGuard running → http://localhost:${PORT}`));
