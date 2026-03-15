const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const db = new DatabaseSync(path.join(__dirname, 'scriptguard.db'));

db.exec(`PRAGMA journal_mode = WAL`);
db.exec(`PRAGMA foreign_keys = ON`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT    UNIQUE NOT NULL,
    username    TEXT    UNIQUE NOT NULL,
    password    TEXT    NOT NULL,
    plan        TEXT    NOT NULL DEFAULT 'free',
    api_key     TEXT    UNIQUE,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS scripts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    description TEXT,
    status      TEXT    NOT NULL DEFAULT 'active',
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS license_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id       INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key             TEXT    UNIQUE NOT NULL,
    label           TEXT,
    expires_at      INTEGER,
    max_executions  INTEGER,
    executions      INTEGER NOT NULL DEFAULT 0,
    hwid            TEXT,
    ip_lock         TEXT,
    status          TEXT    NOT NULL DEFAULT 'active',
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS executions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id     INTEGER NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
    script_id  INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    hwid       TEXT,
    ip         TEXT,
    user_agent TEXT,
    success    INTEGER NOT NULL DEFAULT 1,
    reason     TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    reason     TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(user_id, type, value)
  );

  CREATE INDEX IF NOT EXISTS idx_keys_script  ON license_keys(script_id);
  CREATE INDEX IF NOT EXISTS idx_keys_key     ON license_keys(key);
  CREATE INDEX IF NOT EXISTS idx_exec_script  ON executions(script_id);
  CREATE INDEX IF NOT EXISTS idx_exec_created ON executions(created_at);
`);

module.exports = db;
