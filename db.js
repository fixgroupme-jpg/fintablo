const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'fintablo.db');
const db = new Database(DB_PATH);

// WAL mode for better concurrent reads
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ========== SCHEMA ==========
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'tester' CHECK(role IN ('owner','tester')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_data (
    user_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, key),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_user_data_user ON user_data(user_id);
`);

// ========== USER QUERIES ==========
const stmts = {
  createUser: db.prepare(`INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)`),
  getUserByEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  getUserById: db.prepare(`SELECT id, email, name, role, created_at FROM users WHERE id = ?`),
  listUsers: db.prepare(`SELECT id, email, name, role, created_at FROM users ORDER BY created_at`),
  updateUser: db.prepare(`UPDATE users SET name = ?, role = ? WHERE id = ?`),
  deleteUser: db.prepare(`DELETE FROM users WHERE id = ?`),

  // Data CRUD
  getData: db.prepare(`SELECT key, value, updated_at FROM user_data WHERE user_id = ?`),
  getDataKey: db.prepare(`SELECT value, updated_at FROM user_data WHERE user_id = ? AND key = ?`),
  upsertData: db.prepare(`
    INSERT INTO user_data (user_id, key, value, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `),
  deleteData: db.prepare(`DELETE FROM user_data WHERE user_id = ? AND key = ?`),
};

// Batch save - transaction for atomicity
const saveAllData = db.transaction((userId, dataMap) => {
  for (const [key, value] of Object.entries(dataMap)) {
    stmts.upsertData.run(userId, key, JSON.stringify(value));
  }
});

module.exports = { db, stmts, saveAllData };
