// One-time email codes. The single place codes are created and checked.
//
//   - 6 random digits from crypto.randomInt (not Math.random)
//   - stored as HMAC(server key, id:code), never in plain text
//   - bound to a random ticket the requesting browser holds; both are needed to verify
//   - expire after 10 minutes, single use, 5 wrong guesses burn the ticket
//   - per destination: 60 s between sends and at most 5 sends per hour (checked in the DB,
//     so a restart does not reset it); per IP: at most 20 sends per hour
import { createHmac, randomInt, randomUUID } from 'node:crypto';
import { config } from './config.js';
import { query } from './db.js';
import { randomToken, safeEqual, sha256Hex } from './crypto.js';
import { HttpError } from './http.js';
import { codeEmail, sendEmail } from './notify.js';

export const CODE_MINUTES = 10;
const MAX_ATTEMPTS = 5;
const RESEND_SECONDS = 60;
const PER_DESTINATION_PER_HOUR = 5;
const PER_IP_PER_HOUR = 20;

const ipSends = new Map();
export function resetOtpLimits() {
  ipSends.clear();
}

const codeHash = (id, code) => createHmac('sha256', config.auditHmacKey).update(`otp:${id}:${code}`).digest('hex');

async function checkRateLimits(destination, ip) {
  const now = Date.now();
  const entry = ipSends.get(ip);
  const recent = (entry || []).filter((t) => now - t < 3600_000);
  if (recent.length >= PER_IP_PER_HOUR) throw new HttpError(429, 'Too many codes requested from this network. Try again later.');

  const [row] = await query(
    `SELECT count(*)::int AS n, max(created_at) AS last FROM otp_codes
      WHERE destination = $1 AND created_at > now() - interval '1 hour'`,
    [destination],
  );
  if (row.last && now - new Date(row.last).getTime() < RESEND_SECONDS * 1000) {
    const wait = Math.ceil((RESEND_SECONDS * 1000 - (now - new Date(row.last).getTime())) / 1000);
    throw new HttpError(429, `Please wait ${wait} seconds before asking for another code.`, { code: 'RESEND_COOLDOWN', retryAfter: wait });
  }
  if (row.n >= PER_DESTINATION_PER_HOUR) throw new HttpError(429, 'Too many codes sent to this address in the last hour. Try again later.');
  recent.push(now);
  ipSends.set(ip, recent);
}

/**
 * Create and send a code. Returns the ticket for the browser.
 * With `send: false` nothing is delivered (used to give the same response for unknown
 * accounts, so the API does not reveal which emails or numbers are registered).
 */
export async function issueCode({ purpose, channel, destination, userId = null, ip, send }) {
  // `send` must be an explicit boolean. A default of true once turned an `undefined` from a
  // failed account lookup into "send", emailing codes to addresses that have no account.
  if (typeof send !== 'boolean') throw new TypeError('issueCode: send must be true or false');
  const ticket = randomToken(32);
  // Rate limits and the stored row are the SAME whether or not we deliver. Otherwise the
  // cooldown itself leaks which addresses have accounts: ask twice, and a 429 on the second
  // request would mean "this email is registered".
  await checkRateLimits(destination, ip);

  const id = randomUUID();
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  await query(
    `INSERT INTO otp_codes (id, ticket_hash, purpose, channel, destination, user_id, code_hash, expires_at, ip)
     VALUES ($1,$2,$3,$4,$5,$6,$7, now() + $8 * interval '1 minute', $9)`,
    [id, sha256Hex(ticket), purpose, channel, destination, send ? userId : null, codeHash(id, code), CODE_MINUTES, ip],
  );
  // Not delivered: the code exists only in this stack frame and is discarded, so the row can
  // never be verified. It exists purely so timing and limits look identical.
  if (!send) return { ticket };
  try {
    if (channel !== 'email') throw new Error(`Unsupported channel: ${channel}`);
    await sendEmail({ to: destination, ...codeEmail(purpose, code, CODE_MINUTES) });
  } catch (err) {
    console.error('code delivery failed:', err.message);
    await query('UPDATE otp_codes SET consumed_at = now() WHERE id = $1', [id]);
    throw new HttpError(502, 'We could not send the email right now. Try again in a minute.');
  }
  return { ticket };
}

/**
 * Check a code against its ticket. Returns the code row on success, or throws 400.
 * Every failure gives the same message, so wrong ticket, wrong code and expired code
 * are indistinguishable to the caller.
 */
export async function verifyCode({ ticket, code, purpose }) {
  const generic = new HttpError(400, 'That code is not valid or has expired. Request a new one.');
  if (typeof ticket !== 'string' || typeof code !== 'string') throw generic;
  const clean = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(clean)) throw generic;

  const [row] = await query(
    `SELECT * FROM otp_codes WHERE ticket_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()`,
    [sha256Hex(ticket), purpose],
  );
  if (!row || row.attempts >= MAX_ATTEMPTS) throw generic;

  if (!safeEqual(codeHash(row.id, clean), row.code_hash)) {
    const attempts = row.attempts + 1;
    await query(`UPDATE otp_codes SET attempts = $2${attempts >= MAX_ATTEMPTS ? ', consumed_at = now()' : ''} WHERE id = $1`, [row.id, attempts]);
    throw generic;
  }
  // Single use: only the request that flips consumed_at from NULL wins.
  const used = await query('UPDATE otp_codes SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL RETURNING id', [row.id]);
  if (!used.length) throw generic;
  return row;
}

export const maskEmail = (e) => {
  const [local, domain] = String(e).split('@');
  return `${local.slice(0, 2)}${'•'.repeat(Math.max(1, local.length - 2))}@${domain}`;
};
