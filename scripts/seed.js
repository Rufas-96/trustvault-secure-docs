// npm run seed: create the schema and demo data in an empty database.
import { initDb, closeDb } from '../src/db.js';
import { seedIfEmpty } from '../src/seed.js';

await initDb();
const seeded = await seedIfEmpty();
if (!seeded) console.log('Database already has users; nothing seeded.');
await closeDb();
