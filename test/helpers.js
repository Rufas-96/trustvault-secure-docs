// Test harness: a fresh in-memory Postgres (PGlite), seeded demo data, the real Express
// app on a random port, and a tiny HTTP client that keeps cookies and the CSRF token.
process.env.NODE_ENV = 'test';
process.env.PGLITE_DIR = '';

const { initDb, query, closeDb } = await import('../src/db.js');
const { seedIfEmpty, DEMO_USERS, makePdf } = await import('../src/seed.js');
const { createApp } = await import('../src/app.js');
const { resetLoginThrottle } = await import('../src/auth.js');

export { query, makePdf, DEMO_USERS, resetLoginThrottle };

let server;
export let baseUrl;

export async function start() {
  await initDb();
  await seedIfEmpty({ log: () => {} });
  await new Promise((resolve) => {
    server = createApp().listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
}

export async function stop() {
  await new Promise((resolve) => server.close(resolve));
  await closeDb();
}

export class Client {
  constructor() {
    this.cookie = '';
    this.csrf = '';
  }

  async request(method, path, { json, form, headers = {}, csrf = true } = {}) {
    const h = { ...headers };
    if (this.cookie) h.cookie = this.cookie;
    if (csrf && this.csrf && !['GET', 'HEAD'].includes(method)) h['x-csrf-token'] = this.csrf;
    let body;
    if (json !== undefined) {
      h['content-type'] = 'application/json';
      body = JSON.stringify(json);
    } else if (form) {
      body = form;
    }
    const res = await fetch(baseUrl + path, { method, headers: h, body, redirect: 'manual' });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) this.cookie = setCookie.split(';')[0];
    const type = res.headers.get('content-type') || '';
    const data = type.includes('application/json') ? await res.json() : Buffer.from(await res.arrayBuffer());
    return { status: res.status, data, headers: res.headers };
  }

  get(p, o) { return this.request('GET', p, o); }
  post(p, o) { return this.request('POST', p, o); }
  patch(p, o) { return this.request('PATCH', p, o); }
  del(p, o) { return this.request('DELETE', p, o); }

  async login(email, password) {
    const r = await this.post('/api/auth/login', { json: { email, password } });
    if (r.status !== 200) throw new Error(`login failed for ${email}: ${r.status} ${JSON.stringify(r.data)}`);
    this.csrf = r.data.csrfToken;
    this.user = r.data.user;
    return this;
  }
}

export async function as(key) {
  const u = DEMO_USERS.find((x) => x.key === key);
  return new Client().login(u.email, u.password);
}

/**
 * Admin creates a person, who signs in and replaces the initial password (as the app
 * requires). Returns { client, id, email, password }.
 */
export async function createUser(admin, { role = 'viewer', name = 'Test Person', prefix = 'user' } = {}) {
  const { randomBytes } = await import('node:crypto');
  const email = `${prefix}-${randomBytes(4).toString('hex')}@example.test`;
  const initial = `Init-${randomBytes(9).toString('base64url')}`;
  const created = await admin.post('/api/admin/users', { json: { email, name, role, password: initial } });
  if (created.status !== 201) throw new Error(`create user failed: ${created.status} ${JSON.stringify(created.data)}`);
  const client = await new Client().login(email, initial);
  const password = `Mine-${randomBytes(9).toString('base64url')}`;
  const changed = await client.post('/api/auth/password', { json: { currentPassword: initial, newPassword: password } });
  if (changed.status !== 200) throw new Error(`password change failed: ${JSON.stringify(changed.data)}`);
  return { client, id: created.data.user.id, email, password };
}

export async function docId(title) {
  const [d] = await query('SELECT id FROM documents WHERE title = $1', [title]);
  if (!d) throw new Error(`no document titled ${title}`);
  return d.id;
}

export async function userId(key) {
  const u = DEMO_USERS.find((x) => x.key === key);
  const [row] = await query('SELECT id FROM users WHERE email = $1', [u.email]);
  return row.id;
}

export function fileForm(filename, bytes, fields = {}) {
  const fd = new FormData();
  for (const [k, v] of Object.entries(fields)) fd.append(k, v);
  fd.append('file', new Blob([bytes]), filename);
  return fd;
}

export async function auditCount(where, params = []) {
  const [r] = await query(`SELECT count(*)::int AS n FROM audit_log WHERE ${where}`, params);
  return r.n;
}

// Seeded documents and who can reach them (see src/seed.js):
export const DOCS = {
  salaryVik: 'Salary letter: Vik Varma', // olivia owns; vik read
  handbook: 'Employee handbook 2026', // olivia owns; vik read, omar edit
  reviewOmar: 'Performance review: Omar Lewis', // olivia owns; nobody else
  msaAcme: 'Master services agreement: Acme Corp', // omar owns; vera read (expires in 30 days)
  ndaGlobex: 'NDA: Globex (draft)', // omar owns; nobody else
  auditPapers: 'Q3 audit working papers', // omar owns; olivia read
};
