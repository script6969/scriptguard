const router = require('express').Router();
const db     = require('../db');
const { requireAuth } = require('../middleware/auth');

// GET /api/stats/overview
router.get('/overview', requireAuth, (req, res) => {
  const uid = req.user.id;
  const now = Math.floor(Date.now() / 1000);
  const day = now - 86400;

  const scripts      = db.prepare('SELECT COUNT(*) AS n FROM scripts WHERE user_id = ?').get(uid).n;
  const totalKeys    = db.prepare('SELECT COUNT(*) AS n FROM license_keys WHERE user_id = ?').get(uid).n;
  const activeKeys   = db.prepare("SELECT COUNT(*) AS n FROM license_keys WHERE user_id = ? AND status = 'active'").get(uid).n;
  const totalExecs   = db.prepare('SELECT COUNT(*) AS n FROM executions e JOIN license_keys k ON k.id = e.key_id WHERE k.user_id = ?').get(uid).n;
  const execsToday   = db.prepare('SELECT COUNT(*) AS n FROM executions e JOIN license_keys k ON k.id = e.key_id WHERE k.user_id = ? AND e.created_at > ?').get(uid, day).n;
  const blockedToday = db.prepare('SELECT COUNT(*) AS n FROM executions e JOIN license_keys k ON k.id = e.key_id WHERE k.user_id = ? AND e.success = 0 AND e.created_at > ?').get(uid, day).n;

  // Executions per day for last 14 days
  const chart = db.prepare(`
    SELECT
      date(e.created_at, 'unixepoch') AS day,
      COUNT(*) AS executions,
      SUM(CASE WHEN e.success = 0 THEN 1 ELSE 0 END) AS blocked
    FROM executions e
    JOIN license_keys k ON k.id = e.key_id
    WHERE k.user_id = ? AND e.created_at > ?
    GROUP BY day
    ORDER BY day ASC
  `).all(uid, now - 86400 * 14);

  res.json({ scripts, totalKeys, activeKeys, totalExecs, execsToday, blockedToday, chart });
});

// GET /api/stats/executions?script_id=&limit=
router.get('/executions', requireAuth, (req, res) => {
  const { script_id, limit = 100 } = req.query;
  const uid = req.user.id;

  let where  = 'k.user_id = ?';
  const args = [uid];
  if (script_id) { where += ' AND e.script_id = ?'; args.push(script_id); }

  const rows = db.prepare(`
    SELECT e.*, k.key, s.name AS script_name
    FROM executions e
    JOIN license_keys k ON k.id = e.key_id
    JOIN scripts s ON s.id = e.script_id
    WHERE ${where}
    ORDER BY e.created_at DESC
    LIMIT ?
  `).all(...args, Math.min(+limit, 500));

  res.json(rows);
});

// --- BLACKLIST ---
const blRouter = require('express').Router();

blRouter.get('/', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM blacklist WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(rows);
});

blRouter.post('/', requireAuth, (req, res) => {
  const { type, value, reason } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'type and value are required' });
  if (!['hwid', 'ip', 'key'].includes(type)) return res.status(400).json({ error: 'type must be hwid, ip, or key' });

  try {
    const result = db.prepare(
      'INSERT INTO blacklist (user_id, type, value, reason) VALUES (?, ?, ?, ?)'
    ).run(req.user.id, type, value.trim(), reason || null);
    res.status(201).json(db.prepare('SELECT * FROM blacklist WHERE id = ?').get(result.lastInsertRowid));
  } catch {
    res.status(409).json({ error: 'Already blacklisted' });
  }
});

blRouter.delete('/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM blacklist WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM blacklist WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

module.exports = { statsRouter: router, blacklistRouter: blRouter };
