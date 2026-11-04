// Authentication: server-side sessions, login throttling and CSRF protection.
import { config } from './config.js';
import { query } from './db.js';
import { audit } from './audit.js';
import { DUMMY_PASSWORD_HASH, randomToken, safeEqual, sha256Hex, verifyPassword } from './crypto.js';
import { HttpError } from './http.js';

export const SESSION_COOKIE = config.isProduction ? '__Host-tv_session' : 'tv_session';

function cookieOptions(maxAgeMs) {
  return {
    httpOnly: true, // not readable from JavaScript, so XSS cannot steal it
    secure: config.isProduction, // HTTPS only in production (required by the __Host- prefix)
    sameSite: 'strict', // never sent on cross-site requests
    path: '/',
    maxAge: maxAgeMs,
  };
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

// ── Login throttling ─────────────────────────────────────────────────────────
// Per (IP, email) and per IP. Deliberately no hard account lockout: on a shared demo,
// a lockout would let one person lock everyone else out of the published accounts.
const attempts = new Map(); // key -> { count, resetAt }
const WINDOW_MS = 15 * 60 * 1000;
const LIMITS = { pair: 5, ip: 30 };

function hit(key, limit) {
  const now = Date.now();
  let a = attempts.get(key);
  if (!a || a.resetAt < now) a = { count: 0, resetAt: now + WINDOW_MS };
  a.count += 1;
  attempts.set(key, a);
  return a.count > limit;
}
function isBlocked(key, limit) {
  const a = attempts.get(key);
  return Boolean(a && a.resetAt > Date.now() && a.count >= limit);
}
export function resetLoginThrottle() {
  attempts.clear();
}

export async function login(req, res) {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase().slice(0, 254) : '';
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 200) : '';
  if (!email || !password) throw new HttpError(400, 'Email and password are required');

  const pairKey = `pair:${req.ip}:${email}`;
  const ipKey = `ip:${req.ip}`;
  if (isBlocked(pairKey, LIMITS.pair) || isBlocked(ipKey, LIMITS.ip)) {
    await audit({ actorEmail: email, action: 'auth.login', outcome: 'denied', details: { reason: 'throttled' }, ip: req.ip });
    throw new HttpError(429, 'Too many sign-in attempts. Wait 15 minutes and try again.');
  }

  const [user] = await query('SELECT * FROM users WHERE email = $1', [email]);
  const ok = await verifyPassword(password, user ? user.password_hash : DUMMY_PASSWORD_HASH);

  if (!user || !ok || !user.is_active) {
    hit(pairKey, LIMITS.pair);
    hit(ipKey, LIMITS.ip);
    await audit({
      actor: user && user.is_active ? user : null,
      actorEmail: email,
      action: 'auth.login',
      outcome: 'denied',
      targetUserId: user?.id ?? null,
      details: { reason: !user ? 'unknown email' : !ok ? 'wrong password' : 'account disabled' },
      ip: req.ip,
    });
    // Same message in every case: do not reveal which emails exist or are disabled.
    throw new HttpError(401, 'Email or password is incorrect');
  }

  attempts.delete(pairKey);
  const token = randomToken(32);
  const csrf = randomToken(24);
  const expires = new Date(Date.now() + config.sessionMaxHours * 3600 * 1000);
  await query(
    `INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent) VALUES ($1,$2,$3,$4,$5,$6)`,
    [sha256Hex(token), user.id, csrf, expires, req.ip, String(req.headers['user-agent'] || '').slice(0, 300)],
  );
  await audit({ actor: user, action: 'auth.login', outcome: 'ok', ip: req.ip });

  res.cookie(SESSION_COOKIE, token, cookieOptions(config.sessionMaxHours * 3600 * 1000));
  res.json({ user: publicUser(user), csrfToken: csrf });
}

export async function logout(req, res) {
  if (req.sessionTokenHash) {
    await query('DELETE FROM sessions WHERE token_hash = $1', [req.sessionTokenHash]);
    await audit({ actor: req.user, action: 'auth.logout', outcome: 'ok', ip: req.ip });
  }
  res.clearCookie(SESSION_COOKIE, { ...cookieOptions(0), maxAge: undefined });
  res.json({ ok: true });
}

export function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role, department: u.department };
}

/**
 * Runs on every /api request. Looks the session up in the database each time, so a
 * disabled user or a deleted session is locked out on their next request.
 */
export async function loadSession(req, res, next) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) return next();
  const tokenHash = sha256Hex(token);
  const [row] = await query(
    `SELECT s.token_hash, s.csrf_token, s.last_seen_at, s.expires_at, u.*
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1`,
    [tokenHash],
  );
  if (!row) return next();

  const now = Date.now();
  const idleExpired = now - new Date(row.last_seen_at).getTime() > config.sessionIdleMinutes * 60 * 1000;
  if (!row.is_active || idleExpired || new Date(row.expires_at).getTime() < now) {
    await query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
    return next();
  }

  await query('UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1', [tokenHash]);
  const { token_hash, csrf_token, last_seen_at, expires_at, password_hash, ...user } = row;
  req.user = user;
  req.sessionTokenHash = tokenHash;
  req.csrfToken = csrf_token;
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) throw new HttpError(401, 'Please sign in');
  next();
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * CSRF: every state-changing request from a signed-in user must carry the session's
 * CSRF token in the X-CSRF-Token header. A cross-site form cannot set that header and
 * cannot read the token. SameSite=Strict on the cookie is a second, independent layer.
 */
export function requireCsrf(req, res, next) {
  if (SAFE_METHODS.has(req.method) || !req.user) return next();
  const sent = req.get('x-csrf-token');
  if (!sent || !safeEqual(sent, req.csrfToken)) throw new HttpError(403, 'Missing or invalid CSRF token. Reload the page.');
  next();
}
