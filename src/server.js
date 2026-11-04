import { config } from './config.js';
import { initDb } from './db.js';
import { seedIfEmpty } from './seed.js';
import { createApp } from './app.js';

await initDb();
if (config.seedOnBoot) await seedIfEmpty();

const server = createApp().listen(config.port, () => {
  console.log(`TrustVault listening on http://localhost:${config.port} (${config.databaseUrl ? 'PostgreSQL' : 'PGlite'})`);
});

// Delete sessions that have expired, once an hour. Expired sessions are already refused
// at lookup; this just keeps the table small.
const { query } = await import('./db.js');
setInterval(() => {
  query(`DELETE FROM sessions WHERE expires_at < now() OR last_seen_at < now() - $1 * interval '1 minute'`, [config.sessionIdleMinutes]).catch((e) =>
    console.error('session cleanup failed', e),
  );
}, 3600 * 1000).unref();

for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => server.close(() => process.exit(0)));
