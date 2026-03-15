const router  = require('express').Router();
const { nanoid } = require('nanoid');
const db      = require('../db');
const { requireAuth } = require('../middleware/auth');

function generateKey() {
  const seg = () => nanoid(6).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6).padEnd(6, '0');
  return `SG-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function ownedScript(scriptId, userId) {
  return db.prepare('SELECT id FROM scripts WHERE id = ? AND user_id = ?').get(scriptId, userId);
}

// GET /api/keys?script_id=
router.get('/', requireAuth, (req, res) => {
  const { script_id, status, page = 1, limit = 50 } = req.query;
  const offset = (page - 1) * limit;

  let where  = 'k.user_id = ?';
  const args = [req.user.id];

  if (script_id) { where += ' AND k.script_id = ?'; args.push(script_id); }
  if (status)    { where += ' AND k.status = ?';    args.push(status); }

  const keys = db.prepare(`
    SELECT k.*, s.name AS script_name
    FROM license_keys k
    JOIN scripts s ON s.id = k.script_id
    WHERE ${where}
    ORDER BY k.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...args, limit, offset);

  const total = db.prepare(`
    SELECT COUNT(*) AS n FROM license_keys k WHERE ${where}
  `).get(...args).n;

  res.json({ keys, total, page: +page, pages: Math.ceil(total / limit) });
});

// POST /api/keys — create one or bulk
router.post('/', requireAuth, (req, res) => {
  const { script_id, label, expires_at, max_executions, ip_lock, count = 1 } = req.body;

  if (!script_id) return res.status(400).json({ error: 'script_id is required' });
  if (!ownedScript(script_id, req.user.id))
    return res.status(403).json({ error: 'Script not found or not owned by you' });

  const qty     = Math.min(Math.max(1, parseInt(count)), 500);
  const created = [];
  const insert  = db.prepare(
    'INSERT INTO license_keys (script_id, user_id, key, label, expires_at, max_executions, ip_lock) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );

  const insertMany = db.transaction(() => {
    for (let i = 0; i < qty; i++) {
      const k      = generateKey();
      const result = insert.run(
        script_id, req.user.id, k,
        label || null,
        expires_at ? Math.floor(new Date(expires_at).getTime() / 1000) : null,
        max_executions || null,
        ip_lock || null
      );
      created.push(db.prepare('SELECT * FROM license_keys WHERE id = ?').get(result.lastInsertRowid));
    }
  });

  insertMany();
  res.status(201).json(qty === 1 ? created[0] : created);
});

// GET /api/keys/:id
router.get('/:id', requireAuth, (req, res) => {
  const key = db.prepare('SELECT * FROM license_keys WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });

  const execs = db.prepare(
    'SELECT * FROM executions WHERE key_id = ? ORDER BY created_at DESC LIMIT 50'
  ).all(key.id);

  res.json({ ...key, recent_executions: execs });
});

// PATCH /api/keys/:id
router.patch('/:id', requireAuth, (req, res) => {
  const key = db.prepare('SELECT * FROM license_keys WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });

  const { status, label, expires_at, max_executions, hwid, ip_lock } = req.body;
  const updates = [];
  const params  = [];

  if (status !== undefined)         { updates.push('status = ?');         params.push(status); }
  if (label !== undefined)          { updates.push('label = ?');          params.push(label); }
  if (expires_at !== undefined)     { updates.push('expires_at = ?');     params.push(expires_at ? Math.floor(new Date(expires_at).getTime() / 1000) : null); }
  if (max_executions !== undefined) { updates.push('max_executions = ?'); params.push(max_executions); }
  if (hwid !== undefined)           { updates.push('hwid = ?');           params.push(hwid); }
  if (ip_lock !== undefined)        { updates.push('ip_lock = ?');        params.push(ip_lock); }

  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });

  params.push(req.params.id, req.user.id);
  db.prepare(`UPDATE license_keys SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...params);

  const updated = db.prepare('SELECT * FROM license_keys WHERE id = ?').get(req.params.id);
  res.json(updated);
});

// DELETE /api/keys/:id
router.delete('/:id', requireAuth, (req, res) => {
  const key = db.prepare('SELECT * FROM license_keys WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });

  db.prepare('DELETE FROM license_keys WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// POST /api/keys/reset-hwid/:id
router.post('/reset-hwid/:id', requireAuth, (req, res) => {
  const key = db.prepare('SELECT * FROM license_keys WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });

  db.prepare('UPDATE license_keys SET hwid = NULL WHERE id = ?').run(key.id);
  res.json({ success: true });
});

// POST /api/keys/verify — public verification endpoint (called from scripts)
router.post('/verify', (req, res) => {
  const { key, hwid, script_id } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

  if (!key || !script_id)
    return res.status(400).json({ valid: false, reason: 'key and script_id are required' });

  const record = db.prepare('SELECT * FROM license_keys WHERE key = ? AND script_id = ?').get(key, script_id);

  function deny(reason) {
    if (record) {
      db.prepare(
        'INSERT INTO executions (key_id, script_id, hwid, ip, success, reason) VALUES (?, ?, ?, ?, 0, ?)'
      ).run(record.id, script_id, hwid || null, ip, reason);
    }
    return res.json({ valid: false, reason });
  }

  if (!record)                  return deny('Key not found');
  if (record.status !== 'active') return deny('Key is ' + record.status);
  if (record.expires_at && record.expires_at < Math.floor(Date.now() / 1000))
    return deny('Key has expired');
  if (record.max_executions && record.executions >= record.max_executions)
    return deny('Execution limit reached');

  // HWID check
  if (record.hwid && hwid && record.hwid !== hwid) return deny('HWID mismatch');
  if (!record.hwid && hwid) {
    db.prepare('UPDATE license_keys SET hwid = ? WHERE id = ?').run(hwid, record.id);
  }

  // IP lock check
  if (record.ip_lock && record.ip_lock !== ip) return deny('IP not allowed');

  // Check blacklist
  const script = db.prepare('SELECT user_id FROM scripts WHERE id = ?').get(script_id);
  if (script && hwid) {
    const blocked = db.prepare(
      "SELECT id FROM blacklist WHERE user_id = ? AND type = 'hwid' AND value = ?"
    ).get(script.user_id, hwid);
    if (blocked) return deny('Blacklisted');
  }

  // All good
  db.prepare('UPDATE license_keys SET executions = executions + 1 WHERE id = ?').run(record.id);
  db.prepare(
    'INSERT INTO executions (key_id, script_id, hwid, ip, success) VALUES (?, ?, ?, ?, 1)'
  ).run(record.id, script_id, hwid || null, ip);

  res.json({ valid: true, expires_at: record.expires_at, executions: record.executions + 1 });
});

module.exports = router;
