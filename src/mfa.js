// Time-based one-time passwords (RFC 6238, the scheme every authenticator app uses),
// implemented on Node's crypto so there is no third-party code in the login path.
import { createHmac, randomBytes } from 'node:crypto';
import { decryptFile, encryptFile, safeEqual, sha256Hex } from './crypto.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;
const WINDOW = 1; // accept the previous and next 30 s step to allow for clock drift

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function hotp(key, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', key).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** DIGITS;
  return String(code).padStart(DIGITS, '0');
}

export const currentStep = (now = Date.now()) => Math.floor(now / 1000 / STEP_SECONDS);

/**
 * Check a 6-digit code. Returns the matched time-step, or null.
 * A step at or below `lastStep` is refused, so an intercepted code cannot be replayed.
 */
export function verifyTotp(secretBase32, code, lastStep = 0, now = Date.now()) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const key = base32Decode(secretBase32);
  const step = currentStep(now);
  for (let s = step - WINDOW; s <= step + WINDOW; s++) {
    if (s <= Number(lastStep)) continue;
    if (safeEqual(hotp(key, s), code)) return s;
  }
  return null;
}

export function newSecret() {
  return base32Encode(randomBytes(20)); // 160 bits, as RFC 4226 recommends
}

export function otpauthUri(secret, email) {
  const label = encodeURIComponent(`TrustVault:${email}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=TrustVault&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

// The TOTP secret is encrypted at rest and bound to the user id, so a secret row copied
// onto another account does not decrypt.
export function sealSecret(secret, userId) {
  const { iv, ciphertext, authTag } = encryptFile(Buffer.from(secret), `mfa:${userId}`);
  return [iv, authTag, ciphertext].map((b) => b.toString('base64')).join('.');
}

export function openSecret(sealed, userId) {
  const [iv, authTag, ciphertext] = sealed.split('.').map((s) => Buffer.from(s, 'base64'));
  return decryptFile({ iv, authTag, ciphertext }, `mfa:${userId}`).toString();
}

/** Ten one-time recovery codes like "7KQ4-M2XD". Shown once; only hashes are stored. */
export function newRecoveryCodes() {
  return Array.from({ length: 10 }, () => {
    const raw = base32Encode(randomBytes(5)).slice(0, 8);
    return `${raw.slice(0, 4)}-${raw.slice(4)}`;
  });
}

export const hashRecoveryCode = (code) => sha256Hex(`tv-recovery:${String(code).toUpperCase().replace(/[^A-Z2-7]/g, '')}`);
