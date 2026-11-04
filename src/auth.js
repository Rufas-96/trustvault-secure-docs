// Authentication: passwords, email one-time codes, two-factor (authenticator app / TOTP),
// self sign-up with email verification, password reset, server-side sessions, CSRF and
// Origin checks, throttling, and account security settings.
//
// Sign-in always has the same shape:
//   factor 1  = password | email code
//   factor 2  = authenticator code (or a recovery code), when the account has one
//   session   = created only after every required factor is proven.
import { Router } from 'express';
import { config } from './config.js';
import { query, tx } from './db.js';
import { audit, appendAudit } from './audit.js';
import { DUMMY_PASSWORD_HASH, hashPassword, randomToken, safeEqual, sha256Hex, verifyPassword } from './crypto.js';
import { HttpError, isUuid, str } from './http.js';
import { assertStrongPassword, passwordProblem } from './passwords.js';
import { hashRecoveryCode, newRecoveryCodes, newSecret, openSecret, otpauthUri, sealSecret, verifyTotp } from './mfa.js';
import { issueCode, maskEmail, verifyCode } from './otp.js';
import { channels } from './notify.js';

export const SESSION_COOKIE = config.isProduction ? '__Host-tv_session' : 'tv_session';
const PENDING_LOGIN_MINUTES = 10;
const MAX_SECOND_FACTOR_ATTEMPTS = 5;

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

// Real administrator accounts must use an authenticator app. The published demo accounts are
// exempt because evaluators share them and could otherwise lock each other out.
export const mfaMandatory = (u) => u.role === 'admin' && !u.is_demo;

export function publicUser(u) {
  return {
    id: u.id, email: u.email, name: u.name, role: u.role, department: u.department,
    mfaEnabled: Boolean(u.mfa_enabled), mustChangePassword: Boolean(u.must_change_password),
    mfaRequired: mfaMandatory(u), isDemo: Boolean(u.is_demo),
    emailVerified: Boolean(u.email_verified), signupSource: u.signup_source, passwordChangedAt: u.password_changed_at,
  };
}

/** Which second factor this user needs after `factor1`, or null for none. */
export function secondFactorFor(user) {
  return user.mfa_enabled ? 'totp' : null;
}

// ── Throttling ───────────────────────────────────────────────────────────────
// Per (IP, account) and per IP. Deliberately no hard account lockout: on a shared demo,
// a lockout would let one person lock everyone else out of the published accounts.
const attempts = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const LIMITS = { pair: 5, ip: 30, signupIp: 10 };

function hit(key) {
  const now = Date.now();
  let a = attempts.get(key);
  if (!a || a.resetAt < now) a = { count: 0, resetAt: now + WINDOW_MS * (key.startsWith('signup:') ? 4 : 1) };
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

// ── Session creation (the only place a session is born) ─────────────────────
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

/** Previous successful sign-in and failed attempts since, shown to the user after login. */
async function lastSignIn(userId) {
  const [prev] = await query(
    `SELECT seq, at, ip FROM audit_log WHERE actor_id = $1 AND action = 'auth.login' AND outcome = 'ok' ORDER BY seq DESC LIMIT 1`,
    [userId],
  );
  const [failed] = await query(
    `SELECT count(*)::int AS n FROM audit_log
      WHERE (actor_id = $1 OR target_user_id = $1) AND outcome = 'denied'
        AND action IN ('auth.login', 'auth.second_factor', 'auth.mfa') AND seq > $2`,
    [userId, prev ? prev.seq : 0],
  );
  return prev ? { at: prev.at, ip: prev.ip, failedSince: failed.n } : { at: null, ip: null, failedSince: failed.n };
}

async function completeLogin(req, res, user, factors) {
  const previous = await lastSignIn(user.id);
  const csrf = await createSession(req, res, user);
  await audit({ actor: user, action: 'auth.login', outcome: 'ok', details: { factors }, ip: req.ip });
  res.json({ user: publicUser(user), csrfToken: csrf, lastSignIn: previous });
}

/** Factor 1 is proven. Either finish, or open a pending login for factor 2. */
async function afterFirstFactor(req, res, user, factor1) {
  const second = secondFactorFor(user, factor1);
  if (!second) return completeLogin(req, res, user, [factor1]);

  const ticket = randomToken(32);
  await query('DELETE FROM pending_logins WHERE user_id = $1 OR expires_at < now()', [user.id]);
  await query(
    `INSERT INTO pending_logins (token_hash, user_id, expires_at, ip, factor1, second, otp_ticket_hash)
     VALUES ($1,$2,now() + $3 * interval '1 minute',$4,$5,$6,NULL)`,
    [sha256Hex(ticket), user.id, PENDING_LOGIN_MINUTES, req.ip, factor1, second],
  );
  await audit({ actor: user, action: 'auth.first_factor', outcome: 'ok', details: { factor: factor1, next: second }, ip: req.ip });
  res.json({ mfaRequired: true, mfaToken: ticket, method: second });
}

// ── Factor 1: password ───────────────────────────────────────────────────────
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

  if (!user.email_verified) {
    // Only reachable with the right password, so this reveals nothing to a guesser.
    const { ticket } = await issueCode({ purpose: 'signup', channel: 'email', destination: user.email, userId: user.id, ip: req.ip, send: true });
    throw new HttpError(403, 'Confirm your email first. We have sent you a new code.', { code: 'EMAIL_NOT_VERIFIED', ticket, sentTo: maskEmail(user.email) });
  }
  return afterFirstFactor(req, res, user, 'password');
}

// ── Factor 2 ─────────────────────────────────────────────────────────────────
export async function loginMfa(req, res) {
  const ticket = typeof req.body?.mfaToken === 'string' ? req.body.mfaToken : '';
  if (!ticket) throw new HttpError(400, 'Sign-in expired. Start again.');
  const [pending] = await query(
    `SELECT p.token_hash, p.attempts, p.factor1, p.second, p.otp_ticket_hash, u.*
       FROM pending_logins p JOIN users u ON u.id = p.user_id
      WHERE p.token_hash = $1 AND p.expires_at > now()`,
    [sha256Hex(ticket)],
  );
  if (!pending || !pending.is_active) throw new HttpError(401, 'Sign-in expired. Start again.');

  let method = null;
  const body = req.body ?? {};
  if (pending.second === 'totp') {
    const code = typeof body.code === 'string' ? body.code.replace(/\s/g, '') : '';
    const recovery = typeof body.recoveryCode === 'string' ? body.recoveryCode.trim() : '';
    if (code && pending.mfa_enabled) {
      const step = verifyTotp(openSecret(pending.mfa_secret_enc, pending.id), code, pending.mfa_last_step);
      if (step !== null) {
        // Record the step so the same code cannot be replayed within its 90-second window.
        const updated = await query('UPDATE users SET mfa_last_step = $2 WHERE id = $1 AND mfa_last_step < $2 RETURNING id', [pending.id, step]);
        if (updated.length) method = 'totp';
      }
    } else if (recovery) {
      const used = await query(
        `UPDATE mfa_recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING code_hash`,
        [pending.id, hashRecoveryCode(recovery)],
      );
      if (used.length) method = 'recovery_code';
    }
  }

  if (!method) {
    const n = pending.attempts + 1;
    if (n >= MAX_SECOND_FACTOR_ATTEMPTS) await query('DELETE FROM pending_logins WHERE token_hash = $1', [pending.token_hash]);
    else await query('UPDATE pending_logins SET attempts = $2 WHERE token_hash = $1', [pending.token_hash, n]);
    await audit({ actor: pending, action: 'auth.second_factor', outcome: 'denied', details: { method: pending.second, attempt: n }, ip: req.ip });
    throw new HttpError(401, n >= MAX_SECOND_FACTOR_ATTEMPTS ? 'Too many wrong attempts. Sign in again.' : 'That code is not valid');
  }

  await query('DELETE FROM pending_logins WHERE token_hash = $1', [pending.token_hash]);
  const { token_hash, attempts: _a, factor1, second, otp_ticket_hash, ...user } = pending;
  return completeLogin(req, res, user, [factor1, method]);
}

export async function logout(req, res) {
  if (req.sessionTokenHash) {
    await query('DELETE FROM sessions WHERE token_hash = $1', [req.sessionTokenHash]);
    await audit({ actor: req.user, action: 'auth.logout', outcome: 'ok', ip: req.ip });
  }
  res.clearCookie(SESSION_COOKIE, { ...cookieOptions(0), maxAge: undefined });
  res.json({ ok: true });
}

// ── Public routes: sign-up, code sign-in, password reset ─────────────────────
export const publicAuthRouter = Router();
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const readEmail = (v) => (typeof v === 'string' ? v.trim().toLowerCase().slice(0, 254) : '');
// Demo accounts use an undeliverable domain; never try to email them.
const deliverable = (u) => Boolean(u && u.is_active && u.email_verified && !u.is_demo);

publicAuthRouter.post('/signup', async (req, res) => {
  const signupKey = `signup:${req.ip}`;
  if (isBlocked(signupKey, LIMITS.signupIp)) throw new HttpError(429, 'Too many sign-ups from this network. Try again later.');
  const name = str(req.body?.name, 'Name', { min: 2, max: 100 });
  const email = readEmail(req.body?.email);
  if (!validEmail(email)) throw new HttpError(400, 'Enter a valid email address');
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  assertStrongPassword(password, { email, name });
  hit(signupKey);

  const [existing] = await query('SELECT * FROM users WHERE email = $1', [email]);
  if (existing && (existing.email_verified || existing.signup_source !== 'self')) {
    // Same response as a real sign-up, and no email is sent: do not reveal that the account exists.
    await audit({ actorEmail: email, action: 'auth.signup', outcome: 'denied', targetUserId: existing.id, details: { reason: 'email already registered' }, ip: req.ip });
    const { ticket } = await issueCode({ purpose: 'signup', channel: 'email', destination: email, ip: req.ip, send: false });
    return res.status(201).json({ ticket, sentTo: maskEmail(email) });
  }

  const hash = await hashPassword(password);
  let userId;
  if (existing) {
    // An unverified self sign-up: whoever proves the inbox owns the account. Replacing the
    // password here stops an attacker "pre-registering" someone else's email.
    userId = existing.id;
    await query('UPDATE users SET name = $2, password_hash = $3 WHERE id = $1', [userId, name, hash]);
  } else {
    const { randomUUID } = await import('node:crypto');
    userId = randomUUID();
    await query(
      `INSERT INTO users (id, email, name, role, department, password_hash, email_verified, signup_source)
       VALUES ($1,$2,$3,'viewer',NULL,$4,false,'self')`,
      [userId, email, name, hash],
    );
  }
  await audit({ actorEmail: email, action: 'auth.signup', outcome: 'ok', targetUserId: userId, details: { role: 'viewer' }, ip: req.ip });
  const { ticket } = await issueCode({ purpose: 'signup', channel: 'email', destination: email, userId, ip: req.ip, send: true });
  res.status(201).json({ ticket, sentTo: maskEmail(email) });
});

publicAuthRouter.post('/signup/verify', async (req, res) => {
  const row = await verifyCode({ ticket: req.body?.ticket, code: String(req.body?.code ?? ''), purpose: 'signup' });
  const [user] = await query('UPDATE users SET email_verified = true WHERE id = $1 AND email = $2 RETURNING *', [row.user_id, row.destination]);
  if (!user || !user.is_active) throw new HttpError(400, 'That code is not valid or has expired. Request a new one.');
  await audit({ actor: user, action: 'auth.email_verified', ip: req.ip });
  return afterFirstFactor(req, res, user, 'password');
});

publicAuthRouter.post('/signup/resend', async (req, res) => {
  const email = readEmail(req.body?.email);
  const [user] = await query('SELECT * FROM users WHERE email = $1', [email]);
  const pending = user && user.is_active && !user.email_verified && user.signup_source === 'self';
  const { ticket } = await issueCode({ purpose: 'signup', channel: 'email', destination: email, userId: user?.id, ip: req.ip, send: Boolean(pending) });
  res.json({ ticket, sentTo: maskEmail(email || 'x@x') });
});

publicAuthRouter.post('/email-code/start', async (req, res) => {
  if (!channels().email) throw new HttpError(503, 'Email sign-in codes are not enabled on this deployment');
  const email = readEmail(req.body?.email);
  if (!validEmail(email)) throw new HttpError(400, 'Enter a valid email address');
  const [user] = await query('SELECT * FROM users WHERE email = $1', [email]);
  const { ticket } = await issueCode({ purpose: 'login_email', channel: 'email', destination: email, userId: user?.id, ip: req.ip, send: deliverable(user) });
  // Identical response whether or not the account exists.
  res.json({ ticket, sentTo: maskEmail(email) });
});

publicAuthRouter.post('/email-code/verify', async (req, res) => {
  let row;
  try {
    row = await verifyCode({ ticket: req.body?.ticket, code: String(req.body?.code ?? ''), purpose: 'login_email' });
  } catch (err) {
    await audit({ action: 'auth.login', outcome: 'denied', details: { factor: 'email', reason: 'bad code' }, ip: req.ip });
    throw err;
  }
  const [user] = await query('SELECT * FROM users WHERE id = $1 AND email = $2', [row.user_id, row.destination]);
  if (!deliverable(user)) throw new HttpError(400, 'That code is not valid or has expired. Request a new one.');
  return afterFirstFactor(req, res, user, 'email');
});

publicAuthRouter.post('/password-reset/start', async (req, res) => {
  if (!channels().email) throw new HttpError(503, 'Password reset by email is not enabled on this deployment. Ask an administrator.');
  const email = readEmail(req.body?.email);
  if (!validEmail(email)) throw new HttpError(400, 'Enter a valid email address');
  const [user] = await query('SELECT * FROM users WHERE email = $1', [email]);
  const { ticket } = await issueCode({ purpose: 'password_reset', channel: 'email', destination: email, userId: user?.id, ip: req.ip, send: deliverable(user) });
  if (user) await audit({ actor: null, actorEmail: email, action: 'auth.password_reset_request', targetUserId: user.id, ip: req.ip });
  res.json({ ticket, sentTo: maskEmail(email) });
});

publicAuthRouter.post('/password-reset/complete', async (req, res) => {
  const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
  // Cheap policy checks first, so a weak password does not burn the code.
  const early = passwordProblem(newPassword, {});
  if (early) throw new HttpError(400, early);
  const row = await verifyCode({ ticket: req.body?.ticket, code: String(req.body?.code ?? ''), purpose: 'password_reset' });
  const [user] = await query('SELECT * FROM users WHERE id = $1 AND email = $2', [row.user_id, row.destination]);
  if (!deliverable(user)) throw new HttpError(400, 'That code is not valid or has expired. Request a new one.');
  assertStrongPassword(newPassword, user);
  const hash = await hashPassword(newPassword);
  await tx(async ({ query: q }) => {
    await q('UPDATE users SET password_hash = $2, must_change_password = false, password_changed_at = now() WHERE id = $1', [user.id, hash]);
    // Whoever had the old password, and any stolen cookie, is out.
    await q('DELETE FROM sessions WHERE user_id = $1', [user.id]);
    await q('DELETE FROM pending_logins WHERE user_id = $1', [user.id]);
    await appendAudit(q, { actor: user, action: 'auth.password_reset', ip: req.ip, details: { allSessionsEnded: true } });
  });
  // No session is created: the person signs in normally, including any second factor.
  res.json({ ok: true });
});

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
 * or an admin who has not set up an authenticator yet, can do nothing else until they have.
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
 * Origin check on every state-changing request, including sign-in and sign-up (which have no
 * CSRF token yet). Stops a hostile site from posting forms to sign the victim into an
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

const DEMO_LOCKED = 'The published demo accounts are shared by evaluators, so their password and two-factor settings cannot be changed. Create your own account (Sign up) and try it there.';

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

// Your own sign-in history, including failed attempts against your account.
accountRouter.get('/activity', async (req, res) => {
  const rows = await query(
    `SELECT seq, at, action, outcome, ip, details FROM audit_log
      WHERE (actor_id = $1 OR target_user_id = $1) AND action LIKE 'auth.%'
      ORDER BY seq DESC LIMIT 20`,
    [req.user.id],
  );
  res.json({ activity: rows.map((r) => ({ ...r, seq: Number(r.seq), details: JSON.parse(r.details) })) });
});

// ── Authenticator app (TOTP) ──
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
    // Sessions that were created with weaker sign-in are ended; this one continues.
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
