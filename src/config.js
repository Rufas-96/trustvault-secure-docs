// All configuration comes from environment variables. In production, missing secrets
// stop the server from starting instead of silently falling back to weak defaults.
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const isProduction = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test';

function devKeys() {
  // Local development only: keep generated keys in .data/ so files encrypted
  // yesterday can still be decrypted today. Never used in production.
  const dir = path.resolve('.data');
  const file = path.join(dir, 'dev-keys.json');
  if (existsSync(file)) return JSON.parse(readFileSync(file, 'utf8'));
  mkdirSync(dir, { recursive: true });
  const keys = {
    FILE_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    AUDIT_HMAC_KEY: randomBytes(32).toString('base64'),
  };
  writeFileSync(file, JSON.stringify(keys, null, 2));
  return keys;
}

function secret(name) {
  if (process.env[name]) return process.env[name];
  if (isProduction) throw new Error(`${name} must be set in production`);
  if (isTest) return randomBytes(32).toString('base64');
  return devKeys()[name];
}

function key32(name) {
  const buf = Buffer.from(secret(name), 'base64');
  if (buf.length !== 32) throw new Error(`${name} must be 32 bytes, base64-encoded`);
  return buf;
}

export const config = {
  isProduction,
  isTest,
  port: Number(process.env.PORT) || 3000,
  // Empty DATABASE_URL means embedded PGlite. PGLITE_DIR empty means in-memory.
  databaseUrl: process.env.DATABASE_URL || '',
  pgliteDir: process.env.PGLITE_DIR ?? (isTest ? '' : '.data/pg'),
  fileEncryptionKey: key32('FILE_ENCRYPTION_KEY'),
  auditHmacKey: key32('AUDIT_HMAC_KEY'),
  sessionIdleMinutes: 30,
  sessionMaxHours: 8,
  maxUploadBytes: 10 * 1024 * 1024,
  seedOnBoot: process.env.SEED_ON_BOOT !== 'false',
};
