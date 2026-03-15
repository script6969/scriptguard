const express    = require('express');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const authRouter      = require('./routes/auth');
const scriptsRouter   = require('./routes/scripts');
const keysRouter      = require('./routes/keys');
const { statsRouter, blacklistRouter } = require('./routes/stats');

const app  = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors({ origin: '*' }));
app.use(express.json());

// Rate limiting
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true });
const verifyLimiter = rateLimit({ windowMs: 10 * 1000, max: 30 });

app.use('/api/', apiLimiter);
app.use('/api/keys/verify', verifyLimiter);

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// --- API Routes ---
app.use('/api/auth',       authRouter);
app.use('/api/scripts',    scriptsRouter);
app.use('/api/keys',       keysRouter);
app.use('/api/stats',      statsRouter);
app.use('/api/blacklist',  blacklistRouter);

// Health check
app.get('/api/health', (_, res) => res.json({ status: 'ok', ts: Date.now() }));

// SPA fallback
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
  }
});

// --- Error handler ---
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`ScriptGuard running on http://localhost:${PORT}`);
});
