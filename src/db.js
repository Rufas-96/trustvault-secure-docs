// One small database interface over two drivers:
//   - node-postgres when DATABASE_URL is set (production)
//   - PGlite (real Postgres in WASM) otherwise (local dev and tests)
// Everything else in the app calls query() / tx() and never knows which one it got.
import { readFileSync } from 'node:fs';
import { config } from './config.js';

let driver = null;

function normalise(rows) {
  // PGlite returns bytea as Uint8Array, node-postgres as Buffer. Use Buffer everywhere.
  for (const row of rows) {
    for (const k of Object.keys(row)) {
      if (row[k] instanceof Uint8Array && !Buffer.isBuffer(row[k])) row[k] = Buffer.from(row[k]);
    }
  }
  return rows;
}

async function makePg() {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({
    connectionString: config.databaseUrl,
    ssl: config.databaseUrl.includes('sslmode=disable') ? false : { rejectUnauthorized: false },
    max: 5,
  });
  return {
    async query(text, params = []) {
      const r = await pool.query(text, params);
      return normalise(r.rows);
    },
    async exec(sql) {
      await pool.query(sql);
    },
    async tx(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn({ query: async (t, p = []) => normalise((await client.query(t, p)).rows) });
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
    async close() {
      await pool.end();
    },
  };
}

async function makePglite() {
  const { PGlite } = await import('@electric-sql/pglite');
  const db = config.pgliteDir ? new PGlite(config.pgliteDir) : new PGlite();
  await db.waitReady;
  return {
    async query(text, params = []) {
      return normalise((await db.query(text, params)).rows);
    },
    async exec(sql) {
      await db.exec(sql);
    },
    async tx(fn) {
      return db.transaction(async (t) =>
        fn({ query: async (q, p = []) => normalise((await t.query(q, p)).rows) }),
      );
    },
    async close() {
      await db.close();
    },
  };
}

export async function initDb() {
  if (driver) return driver;
  driver = config.databaseUrl ? await makePg() : await makePglite();
  const schema = readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8');
  await driver.exec(schema);
  return driver;
}

export function query(text, params) {
  return driver.query(text, params);
}

export function tx(fn) {
  return driver.tx(fn);
}

export async function closeDb() {
  if (driver) await driver.close();
  driver = null;
}
