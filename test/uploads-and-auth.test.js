// Upload validation, safe download headers, sessions, CSRF and sign-in throttling.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { as, baseUrl, Client, docId, DOCS, fileForm, makePdf, query, resetLoginThrottle, start, stop } from './helpers.js';

before(start);
after(stop);

const upload = (c, filename, bytes, fields = { title: 'Test', category: 'HR' }) =>
  c.post('/api/documents', { form: fileForm(filename, bytes, fields) });

describe('T-30 upload validation: the bytes must match the claimed type', () => {
  test('accepted: real pdf, png, txt, csv', async () => {
    const c = await as('olivia');
    assert.equal((await upload(c, 'a.pdf', makePdf(['ok']))).status, 201);
    assert.equal((await upload(c, 'a.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0]))).status, 201);
    assert.equal((await upload(c, 'notes.txt', Buffer.from('plain text ✓', 'utf8'))).status, 201);
    assert.equal((await upload(c, 'data.csv', Buffer.from('a,b\n1,2\n'))).status, 201);
  });

  test('rejected: HTML or script disguised as a PDF, executables, SVG, HTML, empty, double extensions', async () => {
    const c = await as('olivia');
    const cases = [
      ['invoice.pdf', Buffer.from('<html><script>alert(document.cookie)</script></html>')],
      ['photo.png', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>')],
      ['setup.exe', Buffer.from('MZ\x90\x00')],
      ['page.html', Buffer.from('<h1>hi</h1>')],
      ['logo.svg', Buffer.from('<svg/>')],
      ['report.pdf.exe', makePdf(['x'])],
      ['empty.pdf', Buffer.alloc(0)],
      ['binary.txt', Buffer.from([0x00, 0x01, 0x02])],
      ['fake.docx', Buffer.from('PK\x03\x04 not really a word file')],
    ];
    for (const [name, bytes] of cases) {
      const r = await upload(c, name, bytes);
      assert.equal(r.status, 400, `${name} should be rejected, got ${r.status}`);
    }
  });

  test('rejected: files over the size limit (413), and nothing is stored', async () => {
    const c = await as('olivia');
    const [{ n: before }] = await query('SELECT count(*)::int AS n FROM documents');
    const big = Buffer.concat([makePdf(['big']), Buffer.alloc(10 * 1024 * 1024 + 1)]);
    assert.equal((await upload(c, 'big.pdf', big)).status, 413);
    const [{ n: afterCount }] = await query('SELECT count(*)::int AS n FROM documents');
    assert.equal(afterCount, before);
  });

  test('rejected: missing title or unknown category', async () => {
    const c = await as('olivia');
    assert.equal((await upload(c, 'a.pdf', makePdf(['x']), { title: '', category: 'HR' })).status, 400);
    assert.equal((await upload(c, 'a.pdf', makePdf(['x']), { title: 'x', category: 'Secret' })).status, 400);
  });

  test('path traversal in the filename is neutralised', async () => {
    const c = await as('olivia');
    const r = await upload(c, '../../etc/passwd.txt', Buffer.from('hello'));
    assert.equal(r.status, 201);
    assert.equal(r.data.document.filename, 'passwd.txt');
  });
});

describe('T-31 downloads cannot run in the browser', () => {
  test('attachment, nosniff, sandbox CSP and no caching', async () => {
    const c = await as('vik');
    const r = await c.get(`/api/documents/${await docId(DOCS.salaryVik)}/download`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-disposition'), /^attachment;/);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.match(r.headers.get('content-security-policy'), /sandbox/);
    assert.match(r.headers.get('cache-control'), /no-store/);
    assert.equal(r.headers.get('content-type'), 'application/pdf');
    assert.ok(r.data.toString('latin1').startsWith('%PDF'));
  });

  test('files are encrypted at rest: the database never holds the plaintext', async () => {
    const [v] = await query(`SELECT v.ciphertext FROM document_versions v JOIN documents d ON d.id = v.document_id WHERE d.title = $1`, [DOCS.salaryVik]);
    assert.ok(!v.ciphertext.toString('latin1').includes('%PDF'));
    assert.ok(!v.ciphertext.toString('latin1').includes('Base salary'));
  });

  test('ciphertext swapped between documents fails to decrypt instead of serving the wrong file', async () => {
    const a = await docId(DOCS.salaryVik);
    const b = await docId(DOCS.handbook);
    const [va] = await query('SELECT iv, auth_tag, ciphertext, sha256 FROM document_versions WHERE document_id = $1 AND version = 1', [a]);
    const [vb] = await query('SELECT iv, auth_tag, ciphertext, sha256 FROM document_versions WHERE document_id = $1 AND version = 1', [b]);
    await query('UPDATE document_versions SET iv = $2, auth_tag = $3, ciphertext = $4, sha256 = $5 WHERE document_id = $1 AND version = 1', [b, va.iv, va.auth_tag, va.ciphertext, va.sha256]);
    try {
      const r = await (await as('vik')).get(`/api/documents/${b}/download?version=1`);
      assert.equal(r.status, 500);
      assert.ok(!Buffer.isBuffer(r.data));
    } finally {
      await query('UPDATE document_versions SET iv = $2, auth_tag = $3, ciphertext = $4, sha256 = $5 WHERE document_id = $1 AND version = 1', [b, vb.iv, vb.auth_tag, vb.ciphertext, vb.sha256]);
    }
  });
});

describe('T-32 sessions and CSRF', () => {
  test('no session, no API', async () => {
    const anon = new Client();
    for (const p of ['/api/documents', '/api/me', '/api/admin/overview', `/api/documents/${await docId(DOCS.salaryVik)}/download`]) {
      assert.equal((await anon.get(p)).status, 401, p);
    }
  });

  test('a forged or guessed session cookie is refused', async () => {
    const c = new Client();
    c.cookie = 'tv_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    assert.equal((await c.get('/api/documents')).status, 401);
  });

  test('state-changing requests without the CSRF token are refused and change nothing', async () => {
    const c = await as('olivia');
    const id = await docId(DOCS.reviewOmar);
    assert.equal((await c.del(`/api/documents/${id}`, { csrf: false })).status, 403);
    assert.equal((await c.del(`/api/documents/${id}`, { csrf: false, headers: { 'x-csrf-token': 'wrong' } })).status, 403);
    const [d] = await query('SELECT deleted_at FROM documents WHERE id = $1', [id]);
    assert.equal(d.deleted_at, null);
  });

  test('the session cookie is HttpOnly and SameSite=Strict', async () => {
    const r = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'vik.viewer@trustvault.demo', password: 'Viewer#Vault2026' }),
    });
    const cookie = r.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
  });

  test('the session token is stored hashed, not in plain text', async () => {
    const c = await as('vik');
    const token = c.cookie.split('=')[1];
    const rows = await query('SELECT token_hash FROM sessions');
    assert.ok(rows.every((r) => r.token_hash !== token));
  });
});

describe('T-33 sign-in', () => {
  test('wrong password and unknown email give the same answer', async () => {
    resetLoginThrottle();
    const a = await new Client().post('/api/auth/login', { json: { email: 'vik.viewer@trustvault.demo', password: 'nope' } });
    const b = await new Client().post('/api/auth/login', { json: { email: 'nobody@trustvault.demo', password: 'nope' } });
    assert.equal(a.status, 401);
    assert.deepEqual(a.data, b.data);
  });

  test('repeated failures are throttled', async () => {
    resetLoginThrottle();
    let last;
    for (let i = 0; i < 7; i++) last = await new Client().post('/api/auth/login', { json: { email: 'olivia.owner@trustvault.demo', password: `guess-${i}` } });
    assert.equal(last.status, 429);
    // Throttling is per IP + email, so the real user on another network is not locked out.
    resetLoginThrottle();
  });

  test('JSON type confusion in the login body is rejected, not crashed on', async () => {
    const r = await new Client().post('/api/auth/login', { json: { email: { $ne: '' }, password: ['x'] } });
    assert.equal(r.status, 400);
  });
});

describe('T-34 admin safety rails', () => {
  test('an admin cannot disable or demote themselves, and published demo accounts are protected', async () => {
    const admin = await as('admin');
    assert.equal((await admin.patch(`/api/admin/users/${admin.user.id}`, { json: { isActive: false } })).status, 400);
    const vik = await as('vik');
    assert.equal((await admin.patch(`/api/admin/users/${vik.user.id}`, { json: { isActive: false } })).status, 400);
  });
});
