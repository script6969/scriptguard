const router = require('express').Router();
const db     = require('../db');
const { requireAuth } = require('../middleware/auth');

const PLAN_LIMITS = { free: 1, pro: 10, enterprise: Infinity };

// GET /api/scripts
router.get('/', requireAuth, (req, res) => {
  const scripts = db.prepare(`
    SELECT s.*,
      COUNT(DISTINCT k.id)  AS total_keys,
      COUNT(DISTINCT CASE WHEN k.status = 'active' THEN k.id END) AS active_keys,
      COUNT(DISTINCT e.id)  AS total_executions,
      COUNT(DISTINCT CASE WHEN e.created_at > unixepoch() - 86400 THEN e.id END) AS executions_today
    FROM scripts s
    LEFT JOIN license_keys k ON k.script_id = s.id
    LEFT JOIN executions   e ON e.script_id = s.id
    WHERE s.user_id = ?
    GROUP BY s.id
    ORDER BY s.created_at DESC
  `).all(req.user.id);

  res.json(scripts);
});

// POST /api/scripts
router.post('/', requireAuth, (req, res) => {
  const limit   = PLAN_LIMITS[req.user.plan] || 1;
  const current = db.prepare('SELECT COUNT(*) AS n FROM scripts WHERE user_id = ?').get(req.user.id).n;

  if (current >= limit)
    return res.status(403).json({ error: `Your ${req.user.plan} plan allows ${limit} script(s). Upgrade to add more.` });

  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const result = db.prepare(
    'INSERT INTO scripts (user_id, name, description) VALUES (?, ?, ?)'
  ).run(req.user.id, name.trim(), (description || '').trim());

  const script = db.prepare('SELECT * FROM scripts WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(script);
});

// GET /api/scripts/:id
router.get('/:id', requireAuth, (req, res) => {
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });
  res.json(script);
});

// PATCH /api/scripts/:id
router.patch('/:id', requireAuth, (req, res) => {
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });

  const { name, description, status } = req.body;
  const updates = [];
  const params  = [];

  if (name)        { updates.push('name = ?');        params.push(name.trim()); }
  if (description !== undefined) { updates.push('description = ?'); params.push(description); }
  if (status)      { updates.push('status = ?');      params.push(status); }

  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });

  params.push(req.params.id, req.user.id);
  db.prepare(`UPDATE scripts SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...params);

  const updated = db.prepare('SELECT * FROM scripts WHERE id = ?').get(req.params.id);
  res.json(updated);
});

// DELETE /api/scripts/:id
router.delete('/:id', requireAuth, (req, res) => {
  const script = db.prepare('SELECT * FROM scripts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!script) return res.status(404).json({ error: 'Script not found' });

  db.prepare('DELETE FROM scripts WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

module.exports = router;
