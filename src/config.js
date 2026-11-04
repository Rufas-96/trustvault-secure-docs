// All configuration comes from environment variables. In production, missing secrets
// stop the server from starting instead of silently falling back to weak defaults.
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const isProduction = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test';

const CLOUDFLARE_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
  '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

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
  const raw = secret(name);
  const buf = Buffer.from(raw, 'base64');
  if (buf.length === 32) return buf;
  // Hosts that generate secrets for you (Render's generateValue) give a random string, not
  // necessarily 32 base64 bytes. Hash it down to 32 bytes, but refuse anything short.
  if (raw.length < 32) throw new Error(`${name} must be at least 32 characters (or 32 bytes base64)`);
  return createHash('sha256').update(raw).digest();
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
  // Proxies whose X-Forwarded-For entries we believe. On Render the chain is
  // client -> Cloudflare -> Render's private network -> app, so skip private ranges and
  // Cloudflare's published ranges (https://www.cloudflare.com/ips/); the first address left
  // is the real client. Anything a client writes into X-Forwarded-For sits further left
  // and is never reached.
  trustProxy: process.env.TRUST_PROXY ?? (isProduction ? ['loopback', 'linklocal', 'uniquelocal', ...CLOUDFLARE_RANGES] : false),
};
