const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const rateLimit = require('express-rate-limit');

const JWT_SECRET  = process.env.JWT_SECRET  || 'prisma-auth-secret-change-me';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'change-me-admin-key';
const PORT        = process.env.PORT        || 5000;
const VALID_ROLES = ['USER', 'MEDIA', 'ADMIN', 'OWNER'];

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1); // needed for rate limiting behind Replit / Railway proxy

// ────────────── Database ──────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function query(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows;
}

async function run(sql, params = []) {
  await pool.query(sql, params);
}

async function getOne(sql, params = []) {
  const rows = await query(sql, params);
  return rows.length > 0 ? rows[0] : null;
}

async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    password        TEXT NOT NULL,
    hwid            TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    banned          INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    locked_until    TIMESTAMPTZ DEFAULT NULL,
    role            TEXT DEFAULT 'USER'
  )`);

  await run(`CREATE TABLE IF NOT EXISTS tokens (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token      TEXT UNIQUE NOT NULL,
    ip         TEXT DEFAULT '',
    remember   INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days'
  )`);

  await run(`CREATE TABLE IF NOT EXISTS captcha (
    id         SERIAL PRIMARY KEY,
    token      TEXT UNIQUE NOT NULL,
    answer     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS hwid_bans (
    id         SERIAL PRIMARY KEY,
    hwid       TEXT UNIQUE NOT NULL,
    reason     TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  // Safe migration for existing DBs
  await run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'USER'`);
}

// Clean expired captchas every 60s
setInterval(async () => {
  try { await run('DELETE FROM captcha WHERE expires_at < NOW()'); } catch (_) {}
}, 60000);

// Clean expired tokens every 10 min
setInterval(async () => {
  try { await run('DELETE FROM tokens WHERE expires_at < NOW()'); } catch (_) {}
}, 600000);

// ────────────── Rate limiting ──────────────
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: 'Too many requests. Try again later.' })
});

app.use('/admin', adminLimiter);

// ────────────── Middleware ──────────────
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.userId   = decoded.uid;
    req.username = decoded.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Invalid admin key' });
  }
  next();
}

async function getHwidBan(hwid) {
  if (!hwid) return null;
  return getOne('SELECT * FROM hwid_bans WHERE hwid = $1', [hwid]);
}

// ────────────── Captcha ──────────────
app.get('/captcha', async (req, res) => {
  const num1  = Math.floor(Math.random() * 50) + 1;
  const num2  = Math.floor(Math.random() * 50) + 1;
  const token = uuidv4();
  await run(
    `INSERT INTO captcha (token, answer, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 minute')`,
    [token, String(num1 + num2)]
  );
  res.json({ token, question: `Captcha: ${num1} + ${num2} = ?` });
});

// ────────────── Register ──────────────
app.post('/register', async (req, res) => {
  try {
    const { username, password, hwid } = req.body;

    if (!username || !password || username.length < 3 || password.length < 4) {
      return res.status(400).json({ error: 'Invalid username or password (min 3/4 chars)' });
    }
    if (!hwid) return res.status(400).json({ error: 'HWID required' });

    const ban = await getHwidBan(hwid);
    if (ban) return res.status(403).json({ error: 'Banned', reason: ban.reason || '' });

    const exists = await getOne('SELECT id FROM users WHERE username = $1', [username]);
    if (exists) return res.status(409).json({ error: 'Username taken' });

    const sameHwid = await getOne('SELECT id FROM users WHERE hwid = $1', [hwid]);
    if (sameHwid) return res.status(409).json({ error: 'HWID already registered' });

    const hash = bcrypt.hashSync(password, 10);
    await run('INSERT INTO users (username, password, hwid) VALUES ($1, $2, $3)', [username, hash, hwid]);
    const user = await getOne('SELECT id, role FROM users WHERE username = $1', [username]);

    const token = jwt.sign({ uid: user.id, sub: username }, JWT_SECRET, { expiresIn: '30d' });
    await run(
      'INSERT INTO tokens (user_id, token, ip, remember) VALUES ($1, $2, $3, 0)',
      [user.id, token, req.ip || '']
    );

    res.json({ token, username, uid: user.id, role: user.role || 'USER' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Login ──────────────
app.post('/login', async (req, res) => {
  try {
    const { username, password, hwid, rememberMe } = req.body;

    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    if (!hwid) return res.status(400).json({ error: 'HWID required' });

    const ban = await getHwidBan(hwid);
    if (ban) return res.status(403).json({ error: 'Banned', reason: ban.reason || '' });

    const user = await getOne('SELECT * FROM users WHERE username = $1', [username]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.banned) return res.status(403).json({ error: 'Banned' });

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({ error: 'Account locked. Try later.' });
    }

    if (!bcrypt.compareSync(password, user.password)) {
      const attempts = (user.failed_attempts || 0) + 1;
      if (attempts >= 5) {
        await run(
          `UPDATE users SET failed_attempts = $1, locked_until = NOW() + INTERVAL '5 minutes' WHERE id = $2`,
          [attempts, user.id]
        );
        return res.status(429).json({ error: 'Too many attempts. Locked 5 min' });
      }
      await run('UPDATE users SET failed_attempts = $1 WHERE id = $2', [attempts, user.id]);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);

    if (!user.hwid) {
      await run('UPDATE users SET hwid = $1 WHERE id = $2', [hwid, user.id]);
    } else if (user.hwid !== hwid) {
      return res.status(403).json({ error: 'HWID mismatch. Account is bound to another PC.' });
    }

    const token = jwt.sign(
      { uid: user.id, sub: user.username },
      JWT_SECRET,
      { expiresIn: rememberMe ? '30d' : '1d' }
    );
    await run(
      'INSERT INTO tokens (user_id, token, ip, remember) VALUES ($1, $2, $3, $4)',
      [user.id, token, req.ip || '', rememberMe ? 1 : 0]
    );

    res.json({ token, username: user.username, uid: user.id, role: user.role || 'USER' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Remember-me ──────────────
app.post('/remember', async (req, res) => {
  try {
    const { token, hwid } = req.body;
    if (!token || !hwid) return res.status(400).json({ error: 'Missing token or HWID' });

    const ban = await getHwidBan(hwid);
    if (ban) return res.status(403).json({ error: 'Banned', reason: ban.reason || '' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const record  = await getOne(
      'SELECT * FROM tokens WHERE token = $1 AND user_id = $2',
      [token, decoded.uid]
    );
    if (!record) return res.status(401).json({ error: 'Token not found' });
    if (!record.remember) return res.status(401).json({ error: 'Session expired, login again' });

    const ip = req.ip || '';
    if (record.ip && record.ip !== ip) {
      return res.status(403).json({ error: 'IP changed. Login again.' });
    }

    const user = await getOne('SELECT * FROM users WHERE id = $1', [decoded.uid]);
    if (!user || user.banned) return res.status(403).json({ error: 'Banned' });
    if (user.hwid && user.hwid !== hwid) return res.status(403).json({ error: 'HWID mismatch' });

    res.json({ ok: true, username: user.username, uid: user.id, role: user.role || 'USER' });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// ────────────── Verify ──────────────
app.post('/verify', authMiddleware, async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ error: 'Missing HWID' });

    const ban = await getHwidBan(hwid);
    if (ban) return res.status(403).json({ error: 'Banned', reason: ban.reason || '' });

    const user = await getOne('SELECT * FROM users WHERE id = $1', [req.userId]);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.banned) return res.status(403).json({ error: 'Banned' });
    if (user.hwid && user.hwid !== hwid) return res.status(403).json({ error: 'HWID mismatch' });

    res.json({ ok: true, username: user.username, uid: user.id, role: user.role || 'USER', banned: !!user.banned });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: List users ──────────────
app.get('/admin/users', adminMiddleware, async (req, res) => {
  try {
    const users = await query(
      'SELECT id, username, hwid, created_at, banned, failed_attempts, locked_until, role FROM users ORDER BY created_at DESC'
    );
    res.json({ users });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: Set role ──────────────
app.post('/admin/setRole', adminMiddleware, async (req, res) => {
  try {
    const { username, role } = req.body;
    if (!username || !role) return res.status(400).json({ error: 'username and role required' });
    if (!VALID_ROLES.includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Valid: ' + VALID_ROLES.join(', ') });
    }
    const user = await getOne('SELECT id FROM users WHERE username = $1', [username]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await run('UPDATE users SET role = $1 WHERE id = $2', [role, user.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: Ban user ──────────────
app.post('/admin/ban/user', adminMiddleware, async (req, res) => {
  try {
    const { username, reason } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });
    const user = await getOne('SELECT id, hwid FROM users WHERE username = $1', [username]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await run('UPDATE users SET banned = 1 WHERE id = $1', [user.id]);
    if (user.hwid) {
      await run(
        'INSERT INTO hwid_bans (hwid, reason) VALUES ($1, $2) ON CONFLICT (hwid) DO NOTHING',
        [user.hwid, reason || '']
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: Ban HWID ──────────────
app.post('/admin/ban', adminMiddleware, async (req, res) => {
  try {
    const { hwid, reason } = req.body;
    if (!hwid) return res.status(400).json({ error: 'HWID required' });
    await run(
      'INSERT INTO hwid_bans (hwid, reason) VALUES ($1, $2) ON CONFLICT (hwid) DO NOTHING',
      [hwid, reason || '']
    );
    await run('UPDATE users SET banned = 1 WHERE hwid = $1', [hwid]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: Unban HWID ──────────────
app.post('/admin/unban', adminMiddleware, async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ error: 'HWID required' });
    await run('DELETE FROM hwid_bans WHERE hwid = $1', [hwid]);
    await run('UPDATE users SET banned = 0 WHERE hwid = $1', [hwid]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: Unban user ──────────────
app.post('/admin/unban/user', adminMiddleware, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });
    const user = await getOne('SELECT id, hwid FROM users WHERE username = $1', [username]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await run('UPDATE users SET banned = 0 WHERE id = $1', [user.id]);
    if (user.hwid) await run('DELETE FROM hwid_bans WHERE hwid = $1', [user.hwid]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: Delete user ──────────────
app.delete('/admin/users/:id', adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await run('DELETE FROM tokens WHERE user_id = $1', [id]);
    await run('DELETE FROM users WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin: List bans ──────────────
app.get('/admin/bans', adminMiddleware, async (req, res) => {
  try {
    const bans = await query('SELECT * FROM hwid_bans ORDER BY created_at DESC');
    res.json({ bans });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ────────────── Admin panel UI ──────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ────────────── Start ──────────────
if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL environment variable is not set.');
  console.error('Create a free PostgreSQL database at https://neon.tech and set DATABASE_URL.');
  process.exit(1);
}

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Auth server on port ${PORT}`));
  })
  .catch(err => {
    console.error('DB init failed:', err.message);
    process.exit(1);
  });
