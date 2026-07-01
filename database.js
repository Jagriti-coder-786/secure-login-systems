const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.resolve(__dirname, 'secure_auth.db');

// Ensure db directory exists
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database', err);
  } else {
    console.log('Database connected successfully.');
    initializeSchema();
  }
});

// Helper to run query in a Promise
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

// Helper to get single row in a Promise
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// Helper to get all rows in a Promise
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Initialize tables with secure schema
function initializeSchema() {
  db.serialize(() => {
    // 1. Users Table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        two_factor_secret TEXT,
        two_factor_enabled INTEGER DEFAULT 0,
        two_factor_recovery_codes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 2. Sessions Table
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // 3. Security Audit Logs Table
    db.run(`
      CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 4. Failed Logins & Lockout Tracking Table
    db.run(`
      CREATE TABLE IF NOT EXISTS failed_logins (
        username TEXT PRIMARY KEY,
        attempts INTEGER DEFAULT 0,
        last_attempt DATETIME,
        locked_until DATETIME
      )
    `);

    console.log('Database tables initialized.');
  });
}

// Security Logs Helper
async function logSecurityEvent(userId, eventType, ipAddress, userAgent, details = '') {
  try {
    await run(
      `INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details) 
       VALUES (?, ?, ?, ?, ?)`,
      [userId, eventType, ipAddress, userAgent, details]
    );
  } catch (err) {
    console.error('Logging security event failed', err);
  }
}

module.exports = {
  db,
  
  // User Management
  createUser: async (username, email, passwordHash) => {
    return run(
      `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`,
      [username, email, passwordHash]
    );
  },

  getUserByUsername: async (username) => {
    return get(`SELECT * FROM users WHERE username = ?`, [username]);
  },

  getUserByEmail: async (email) => {
    return get(`SELECT * FROM users WHERE email = ?`, [email]);
  },

  getUserById: async (id) => {
    return get(`SELECT * FROM users WHERE id = ?`, [id]);
  },

  updateUserPassword: async (userId, newPasswordHash) => {
    return run(
      `UPDATE users SET password_hash = ? WHERE id = ?`,
      [newPasswordHash, userId]
    );
  },

  updateUser2FA: async (userId, secret, enabled, recoveryCodesJson) => {
    return run(
      `UPDATE users SET two_factor_secret = ?, two_factor_enabled = ?, two_factor_recovery_codes = ? WHERE id = ?`,
      [secret, enabled, recoveryCodesJson, userId]
    );
  },

  // Session Management
  createSession: async (sessionId, userId, ipAddress, userAgent, expiresAt) => {
    return run(
      `INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)`,
      [sessionId, userId, ipAddress, userAgent, expiresAt]
    );
  },

  getSession: async (sessionId) => {
    return get(`SELECT * FROM sessions WHERE id = ? AND revoked = 0 AND datetime(expires_at) > datetime('now')`, [sessionId]);
  },

  revokeSession: async (sessionId, userId) => {
    return run(`UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?`, [sessionId, userId]);
  },

  revokeAllOtherSessions: async (sessionId, userId) => {
    return run(`UPDATE sessions SET revoked = 1 WHERE id != ? AND user_id = ?`, [sessionId, userId]);
  },

  getUserActiveSessions: async (userId) => {
    return all(
      `SELECT id, ip_address, user_agent, created_at, expires_at 
       FROM sessions 
       WHERE user_id = ? AND revoked = 0 AND datetime(expires_at) > datetime('now')
       ORDER BY created_at DESC`,
      [userId]
    );
  },

  // Audit Logs
  logSecurityEvent,

  getSecurityLogs: async (userId, limit = 50) => {
    return all(
      `SELECT event_type, ip_address, user_agent, details, timestamp 
       FROM security_logs 
       WHERE user_id = ? OR (user_id IS NULL AND event_type IN ('LOGIN_FAILURE', 'LOCKOUT'))
       ORDER BY timestamp DESC LIMIT ?`,
      [userId, limit]
    );
  },

  // Failed Login & Lockout Management
  getFailedLogins: async (username) => {
    return get(`SELECT * FROM failed_logins WHERE username = ?`, [username]);
  },

  recordFailedLogin: async (username) => {
    const record = await get(`SELECT * FROM failed_logins WHERE username = ?`, [username]);
    const now = new Date().toISOString();
    if (!record) {
      return run(
        `INSERT INTO failed_logins (username, attempts, last_attempt, locked_until) VALUES (?, 1, ?, NULL)`,
        [username, now]
      );
    } else {
      const attempts = record.attempts + 1;
      let lockedUntil = null;
      // After 5 attempts, lock for 15 minutes
      if (attempts >= 5) {
        const lockoutTime = new Date();
        lockoutTime.setMinutes(lockoutTime.getMinutes() + 15);
        lockedUntil = lockoutTime.toISOString();
      }
      return run(
        `UPDATE failed_logins SET attempts = ?, last_attempt = ?, locked_until = ? WHERE username = ?`,
        [attempts, now, lockedUntil, username]
      );
    }
  },

  resetFailedLogins: async (username) => {
    return run(`DELETE FROM failed_logins WHERE username = ?`, [username]);
  }
};
