// Authentication: passwords, two-factor (TOTP), server-side sessions, CSRF and Origin
// checks, sign-in throttling, password changes and session management.
import { Router } from 'express';
import { config } from './config.js';
import { query, tx } from './db.js';
import { audit, appendAudit } from './audit.js';
import { DUMMY_PASSWORD_HASH, hashPassword, randomToken, safeEqual, sha256Hex, verifyPassword } from './crypto.js';
import { HttpError, isUuid } from './http.js';
import { assertStrongPassword } from './passwords.js';
import { hashRecoveryCode, newRecoveryCodes, newSecret, openSecret, otpauthUri, sealSecret, verifyTotp } from './mfa.js';

export const SESSION_COOKIE = config.isProduction ? '__Host-tv_session' : 'tv_session';
const PENDING_LOGIN_MINUTES = 5;
const MAX_MFA_ATTEMPTS = 5;

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

export function publicUser(u) {
  return {
    id: u.id, email: u.email, name: u.name, role: u.role, department: u.department,
    mfaEnabled: Boolean(u.mfa_enabled), mustChangePassword: Boolean(u.must_change_password),
    mfaRequired: mfaMandatory(u), isDemo: Boolean(u.is_demo),
  };
}

// Real administrator accounts must use two-factor sign-in. The published demo accounts are
// exempt because evaluators share them and could otherwise lock each other out.
export const mfaMandatory = (u) => u.role === 'admin' && !u.is_demo;

// ── Sign-in throttling ───────────────────────────────────────────────────────
// Per (IP, email) and per IP. Deliberately no hard account lockout: on a shared demo,
// a lockout would let one person lock everyone else out of the published accounts.
const attempts = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const LIMITS = { pair: 5, ip: 30 };

function hit(key) {
  const now = Date.now();
  let a = attempts.get(key);
  if (!a || a.resetAt < now) a = { count: 0, resetAt: now + WINDOW_MS };
  a.count += 1;
  attempts.set(key, a);
}
function isBlocked(key, limit) {
  const a = attempts.get(key);
  return Boolean(a && a.resetAt > Date.now() && a.count >= limit);
}
export function resetLoginThrottle() {
  attempts.clear();
}

async function createSession(req, res, user) {
  const token = randomToken(32);
  const csrf = randomToken(24);
  const expires = new Date(Date.now() + config.sessionMaxHours * 3600 * 1000);
  await query(
    `INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent) VALUES ($1,$2,$3,$4,$5,$6)`,
    [sha256Hex(token), user.id, csrf, expires, req.ip, String(req.headers['user-agent'] || '').slice(0, 300)],
  );
  res.cookie(SESSION_COOKIE, token, cookieOptions(config.sessionMaxHours * 3600 * 1000));
  return csrf;
}

// ── Step 1: password ─────────────────────────────────────────────────────────
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
  // Always run scrypt, even for unknown emails, so timing does not reveal who has an account.
  const ok = await verifyPassword(password, user ? user.password_hash : DUMMY_PASSWORD_HASH);

  if (!user || !ok || !user.is_active) {
    hit(pairKey);
    hit(ipKey);
    await audit({
      actor: user && user.is_active ? user : null, actorEmail: email, action: 'auth.login', outcome: 'denied',
      targetUserId: user?.id ?? null, ip: req.ip,
      details: { reason: !user ? 'unknown email' : !ok ? 'wrong password' : 'account disabled' },
    });
    // Same message in every case: do not reveal which emails exist or are disabled.
    throw new HttpError(401, 'Email or password is incorrect');
  }
  attempts.delete(pairKey);

  if (user.mfa_enabled) {
    // Password was right, but no session yet: issue a short-lived ticket for step 2.
    const ticket = randomToken(32);
    await query('DELETE FROM pending_logins WHERE user_id = $1 OR expires_at < now()', [user.id]);
    await query(`INSERT INTO pending_logins (token_hash, user_id, expires_at, ip) VALUES ($1,$2,now() + $3 * interval '1 minute',$4)`, [
      sha256Hex(ticket), user.id, PENDING_LOGIN_MINUTES, req.ip,
    ]);
    await audit({ actor: user, action: 'auth.password_ok', outcome: 'ok', details: { next: 'mfa' }, ip: req.ip });
    return res.json({ mfaRequired: true, mfaToken: ticket });
  }

  const csrf = await createSession(req, res, user);
  await audit({ actor: user, action: 'auth.login', outcome: 'ok', details: { mfa: false }, ip: req.ip });
  res.json({ user: publicUser(user), csrfToken: csrf });
}

// ── Step 2: one-time code or recovery code ───────────────────────────────────
export async function loginMfa(req, res) {
  const ticket = typeof req.body?.mfaToken === 'string' ? req.body.mfaToken : '';
  const code = typeof req.body?.code === 'string' ? req.body.code.replace(/\s/g, '') : '';
  const recovery = typeof req.body?.recoveryCode === 'string' ? req.body.recoveryCode.trim() : '';
  if (!ticket || (!code && !recovery)) throw new HttpError(400, 'Enter the 6-digit code from your authenticator app');

  const [pending] = await query(
    `SELECT p.token_hash, p.attempts, u.* FROM pending_logins p JOIN users u ON u.id = p.user_id
      WHERE p.token_hash = $1 AND p.expires_at > now()`,
    [sha256Hex(ticket)],
  );
  if (!pending || !pending.is_active || !pending.mfa_enabled) throw new HttpError(401, 'Sign-in expired. Enter your password again.');

  let method = null;
  if (code) {
    const step = verifyTotp(openSecret(pending.mfa_secret_enc, pending.id), code, pending.mfa_last_step);
    if (step !== null) {
      // Record the step so the same code cannot be replayed within its 90-second window.
      const updated = await query('UPDATE users SET mfa_last_step = $2 WHERE id = $1 AND mfa_last_step < $2 RETURNING id', [pending.id, step]);
      if (updated.length) method = 'totp';
    }
  } else {
    const used = await query(
      `UPDATE mfa_recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING code_hash`,
      [pending.id, hashRecoveryCode(recovery)],
    );
    if (used.length) method = 'recovery_code';
  }

  if (!method) {
    const attemptsSoFar = pending.attempts + 1;
    if (attemptsSoFar >= MAX_MFA_ATTEMPTS) await query('DELETE FROM pending_logins WHERE token_hash = $1', [pending.token_hash]);
    else await query('UPDATE pending_logins SET attempts = $2 WHERE token_hash = $1', [pending.token_hash, attemptsSoFar]);
    await audit({ actor: pending, action: 'auth.mfa', outcome: 'denied', details: { reason: code ? 'wrong code' : 'wrong recovery code', attempt: attemptsSoFar }, ip: req.ip });
    throw new HttpError(401, attemptsSoFar >= MAX_MFA_ATTEMPTS ? 'Too many wrong codes. Sign in again.' : 'That code is not valid');
  }

  await query('DELETE FROM pending_logins WHERE token_hash = $1', [pending.token_hash]);
  const csrf = await createSession(req, res, pending);
  await audit({ actor: pending, action: 'auth.login', outcome: 'ok', details: { mfa: method }, ip: req.ip });
  const { token_hash, attempts: _a, ...user } = pending;
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

// ── Per-request session check ────────────────────────────────────────────────
/**
 * Runs on every /api request. Looks the session up in the database each time, so a
 * disabled user or a deleted session is locked out on their next request.
 */
export async function loadSession(req, res, next) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) return next();
  const tokenHash = sha256Hex(token);
  const [row] = await query(
    `SELECT s.token_hash, s.csrf_token, s.last_seen_at, s.expires_at, s.id AS session_id, u.*
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
  // Secrets never ride along on req.user.
  const { token_hash, csrf_token, last_seen_at, expires_at, session_id, password_hash, mfa_secret_enc, ...user } = row;
  req.user = user;
  req.sessionTokenHash = tokenHash;
  req.sessionId = session_id;
  req.csrfToken = csrf_token;
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) throw new HttpError(401, 'Please sign in');
  next();
}

/**
 * Gate for everything except the account pages: a user who must change their password,
 * or an admin who has not set up two-factor yet, can do nothing else until they have.
 */
export function requireAccountReady(req, res, next) {
  if (req.user.must_change_password) throw new HttpError(403, 'Choose a new password before continuing', { code: 'PASSWORD_CHANGE_REQUIRED' });
  if (mfaMandatory(req.user) && !req.user.mfa_enabled) throw new HttpError(403, 'Administrators must set up two-factor sign-in before continuing', { code: 'MFA_SETUP_REQUIRED' });
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

/**
 * Origin check on every state-changing request, including sign-in (which has no CSRF
 * token yet). Stops a hostile site from posting a login form to sign the victim into an
 * attacker's account. Requests with no Origin header (curl, server-to-server) carry no
 * ambient browser credentials, so they are still subject to the CSRF token check above.
 */
export function requireSameOrigin(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  const origin = req.get('origin');
  if (!origin) return next();
  let host;
  try {
    host = new URL(origin).host;
  } catch {
    throw new HttpError(403, 'Cross-origin request refused');
  }
  if (host !== req.get('host')) throw new HttpError(403, 'Cross-origin request refused');
  next();
}

// ── Account routes: /api/auth/* for the signed-in user ───────────────────────
export const accountRouter = Router();

const DEMO_LOCKED = 'The published demo accounts are shared by evaluators, so their password and two-factor settings cannot be changed. Sign in as the admin, create your own account under People, and try it there.';

accountRouter.post('/password', async (req, res) => {
  if (req.user.is_demo) throw new HttpError(400, DEMO_LOCKED);
  const current = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
  const next = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
  const [row] = await query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  if (!(await verifyPassword(current.slice(0, 200), row.password_hash))) {
    await audit({ actor: req.user, action: 'auth.password_change', outcome: 'denied', details: { reason: 'wrong current password' }, ip: req.ip });
    throw new HttpError(400, 'Your current password is not correct');
  }
  assertStrongPassword(next, req.user);
  if (await verifyPassword(next.slice(0, 200), row.password_hash)) throw new HttpError(400, 'Choose a password different from your current one');

  const hash = await hashPassword(next);
  await tx(async ({ query: q }) => {
    await q('UPDATE users SET password_hash = $2, must_change_password = false, password_changed_at = now() WHERE id = $1', [req.user.id, hash]);
    // Anyone else holding a session for this account (a stolen cookie, an old laptop) is out.
    await q('DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2', [req.user.id, req.sessionTokenHash]);
    await appendAudit(q, { actor: req.user, action: 'auth.password_change', ip: req.ip, details: { otherSessionsEnded: true } });
  });
  res.json({ ok: true });
});

accountRouter.get('/sessions', async (req, res) => {
  const rows = await query(
    `SELECT id, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions
      WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC`,
    [req.user.id],
  );
  res.json({ sessions: rows.map((s) => ({ ...s, current: s.id === req.sessionId })) });
});

accountRouter.delete('/sessions/:sid', async (req, res) => {
  if (!isUuid(req.params.sid)) throw new HttpError(404, 'Session not found');
  // user_id in the WHERE: you can only end your own sessions.
  const rows = await query('DELETE FROM sessions WHERE id = $1 AND user_id = $2 RETURNING id', [req.params.sid, req.user.id]);
  if (!rows.length) throw new HttpError(404, 'Session not found');
  await audit({ actor: req.user, action: 'auth.session_revoke', ip: req.ip, details: { session: req.params.sid } });
  res.json({ ok: true });
});

accountRouter.post('/sessions/revoke-others', async (req, res) => {
  const rows = await query('DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2 RETURNING id', [req.user.id, req.sessionTokenHash]);
  await audit({ actor: req.user, action: 'auth.session_revoke', ip: req.ip, details: { others: rows.length } });
  res.json({ ended: rows.length });
});

// Two-factor setup: (1) generate a secret, (2) prove the app works with a code, (3) enabled.
accountRouter.post('/mfa/setup', async (req, res) => {
  if (req.user.is_demo) throw new HttpError(400, DEMO_LOCKED);
  if (req.user.mfa_enabled) throw new HttpError(400, 'Two-factor sign-in is already on');
  const secret = newSecret();
  await query('UPDATE users SET mfa_secret_enc = $2 WHERE id = $1', [req.user.id, sealSecret(secret, req.user.id)]);
  const uri = otpauthUri(secret, req.user.email);
  const { default: QRCode } = await import('qrcode');
  const qrSvg = await QRCode.toString(uri, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' });
  res.json({ secret, otpauthUri: uri, qrDataUrl: `data:image/svg+xml;base64,${Buffer.from(qrSvg).toString('base64')}` });
});

accountRouter.post('/mfa/enable', async (req, res) => {
  if (req.user.is_demo) throw new HttpError(400, DEMO_LOCKED);
  const [row] = await query('SELECT mfa_secret_enc, mfa_enabled, mfa_last_step FROM users WHERE id = $1', [req.user.id]);
  if (row.mfa_enabled) throw new HttpError(400, 'Two-factor sign-in is already on');
  if (!row.mfa_secret_enc) throw new HttpError(400, 'Start setup first');
  const step = verifyTotp(openSecret(row.mfa_secret_enc, req.user.id), String(req.body?.code ?? '').replace(/\s/g, ''), row.mfa_last_step);
  if (step === null) throw new HttpError(400, 'That code is not valid. Check the time on your phone and try the newest code.');

  const codes = newRecoveryCodes();
  await tx(async ({ query: q }) => {
    await q('UPDATE users SET mfa_enabled = true, mfa_last_step = $2 WHERE id = $1', [req.user.id, step]);
    await q('DELETE FROM mfa_recovery_codes WHERE user_id = $1', [req.user.id]);
    for (const c of codes) await q('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1,$2)', [req.user.id, hashRecoveryCode(c)]);
    // Sessions that were created with a password alone are ended; this one continues.
    await q('DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2', [req.user.id, req.sessionTokenHash]);
    await appendAudit(q, { actor: req.user, action: 'auth.mfa_enable', ip: req.ip });
  });
  res.json({ recoveryCodes: codes });
});

accountRouter.post('/mfa/disable', async (req, res) => {
  if (mfaMandatory(req.user)) throw new HttpError(400, 'Administrators cannot turn off two-factor sign-in');
  const [row] = await query('SELECT password_hash, mfa_secret_enc, mfa_enabled, mfa_last_step FROM users WHERE id = $1', [req.user.id]);
  if (!row.mfa_enabled) throw new HttpError(400, 'Two-factor sign-in is not on');
  const passwordOk = await verifyPassword(String(req.body?.password ?? '').slice(0, 200), row.password_hash);
  const step = verifyTotp(openSecret(row.mfa_secret_enc, req.user.id), String(req.body?.code ?? '').replace(/\s/g, ''), row.mfa_last_step);
  if (!passwordOk || step === null) {
    await audit({ actor: req.user, action: 'auth.mfa_disable', outcome: 'denied', ip: req.ip });
    throw new HttpError(400, 'Password or code is not correct');
  }
  await tx(async ({ query: q }) => {
    await q('UPDATE users SET mfa_enabled = false, mfa_secret_enc = NULL, mfa_last_step = $2 WHERE id = $1', [req.user.id, step]);
    await q('DELETE FROM mfa_recovery_codes WHERE user_id = $1', [req.user.id]);
    await appendAudit(q, { actor: req.user, action: 'auth.mfa_disable', ip: req.ip });
  });
  res.json({ ok: true });
});

accountRouter.get('/mfa/recovery-codes', async (req, res) => {
  const [r] = await query('SELECT count(*)::int AS n FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL', [req.user.id]);
  res.json({ remaining: r.n });
});
