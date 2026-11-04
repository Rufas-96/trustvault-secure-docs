// One user cannot reach another user's documents, through any document route.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { as, auditCount, docId, DOCS, fileForm, makePdf, query, start, stop, userId } from './helpers.js';

before(start);
after(stop);

// Every route that takes a document id, with the request that would abuse it.
function everyDocumentRoute(id, grantId = '00000000-0000-4000-8000-000000000000') {
  return [
    ['view metadata', (c) => c.get(`/api/documents/${id}`)],
    ['list versions', (c) => c.get(`/api/documents/${id}/versions`)],
    ['download current', (c) => c.get(`/api/documents/${id}/download`)],
    ['download version 1', (c) => c.get(`/api/documents/${id}/download?version=1`)],
    ['rename', (c) => c.patch(`/api/documents/${id}`, { json: { title: 'pwned' } })],
    ['upload new version', (c) => c.post(`/api/documents/${id}/versions`, { form: fileForm('x.pdf', makePdf(['pwned'])) })],
    ['delete', (c) => c.del(`/api/documents/${id}`)],
    ['restore', (c) => c.post(`/api/documents/${id}/restore`)],
    ['list grants', (c) => c.get(`/api/documents/${id}/grants`)],
    ['grant self', (c) => c.post(`/api/documents/${id}/grants`, { json: { userId: c.user.id, permission: 'edit' } })],
    ['revoke grant', (c) => c.del(`/api/documents/${id}/grants/${grantId}`)],
    ['view activity', (c) => c.get(`/api/documents/${id}/activity`)],
  ];
}

async function snapshot(id) {
  const [d] = await query('SELECT title, deleted_at, current_version FROM documents WHERE id = $1', [id]);
  const [g] = await query('SELECT count(*)::int AS n FROM grants WHERE document_id = $1 AND revoked_at IS NULL', [id]);
  return { ...d, grants: g.n };
}

describe('T-01/T-02 a user with no grant is refused on every document route', () => {
  for (const [who, title] of [
    ['vik', DOCS.reviewOmar], // viewer vs another person's private HR record
    ['vera', DOCS.ndaGlobex], // external partner vs a different client's NDA
    ['omar', DOCS.salaryVik], // an owner vs another owner's private document
    ['olivia', DOCS.ndaGlobex],
  ]) {
    test(`${who} cannot reach "${title}"`, async () => {
      const id = await docId(title);
      const [g] = await query('SELECT id FROM grants WHERE document_id = $1 LIMIT 1', [id]);
      const c = await as(who);
      const beforeState = await snapshot(id);
      for (const [name, call] of everyDocumentRoute(id, g?.id)) {
        const r = await call(c);
        assert.equal(r.status, 404, `${name} should be refused with 404, got ${r.status}`);
        assert.ok(!Buffer.isBuffer(r.data) || !r.data.toString('latin1').startsWith('%PDF'), `${name} leaked file bytes`);
      }
      assert.deepEqual(await snapshot(id), beforeState, 'refused requests must not change anything');
    });
  }
});

describe('T-03 list and search never return documents the caller cannot read', () => {
  test('vik sees exactly his two shared documents, whatever the filters', async () => {
    const c = await as('vik');
    const allowed = new Set([await docId(DOCS.salaryVik), await docId(DOCS.handbook)]);
    const queries = ['', '?q=review', '?q=NDA', '?owner=omar', '?owner=olivia', '?category=Legal', '?category=HR', '?q=%25', '?q=_', '?scope=shared', '?from=2000-01-01&to=2100-01-01'];
    for (const qs of queries) {
      const r = await c.get(`/api/documents${qs}`);
      assert.equal(r.status, 200);
      for (const d of r.data.documents) assert.ok(allowed.has(d.id), `search ${qs} leaked "${d.title}"`);
    }
    const all = await c.get('/api/documents');
    assert.equal(all.data.documents.length, 2);
  });

  test('vera (external) sees only the Acme MSA', async () => {
    const c = await as('vera');
    const r = await c.get('/api/documents?q=');
    assert.deepEqual(r.data.documents.map((d) => d.title), [DOCS.msaAcme]);
  });

  test('a LIKE wildcard in the search box is matched literally, not as "everything"', async () => {
    const c = await as('olivia');
    const r = await c.get('/api/documents?q=%25');
    assert.equal(r.data.documents.length, 0);
  });
});

describe('T-06 read access is only read access', () => {
  test('vik (read) can view and download but not change, delete or share the handbook', async () => {
    const id = await docId(DOCS.handbook);
    const c = await as('vik');
    assert.equal((await c.get(`/api/documents/${id}`)).status, 200);
    assert.equal((await c.get(`/api/documents/${id}/download`)).status, 200);
    assert.equal((await c.patch(`/api/documents/${id}`, { json: { title: 'x' } })).status, 404);
    assert.equal((await c.post(`/api/documents/${id}/versions`, { form: fileForm('a.pdf', makePdf(['x'])) })).status, 404);
    assert.equal((await c.del(`/api/documents/${id}`)).status, 404);
    assert.equal((await c.get(`/api/documents/${id}/grants`)).status, 404);
    assert.equal((await c.post(`/api/documents/${id}/grants`, { json: { userId: await userId('vera'), permission: 'read' } })).status, 404);
  });
});

describe('T-07 edit access cannot delete, share or see who else has access', () => {
  test('omar (edit on handbook) can rename and add a version, nothing more', async () => {
    const id = await docId(DOCS.handbook);
    const c = await as('omar');
    assert.equal((await c.patch(`/api/documents/${id}`, { json: { description: 'Updated by Legal' } })).status, 200);
    assert.equal((await c.post(`/api/documents/${id}/versions`, { form: fileForm('handbook-v2.pdf', makePdf(['v2'])) })).status, 201);
    assert.equal((await c.del(`/api/documents/${id}`)).status, 404);
    assert.equal((await c.get(`/api/documents/${id}/grants`)).status, 404);
    assert.equal((await c.get(`/api/documents/${id}/activity`)).status, 404);
    assert.equal((await c.post(`/api/documents/${id}/grants`, { json: { userId: await userId('vera'), permission: 'read' } })).status, 404);
  });
});

describe('T-08 a viewer is capped at read even if an edit grant exists in the database', () => {
  test('a stray edit grant does not let a viewer change a document', async () => {
    const id = await docId(DOCS.salaryVik);
    await query(`UPDATE grants SET permission = 'edit' WHERE document_id = $1 AND grantee_id = $2`, [id, await userId('vik')]);
    const c = await as('vik');
    assert.equal((await c.patch(`/api/documents/${id}`, { json: { title: 'raised salary' } })).status, 404);
    const list = await c.get('/api/documents');
    assert.equal(list.data.documents.find((d) => d.id === id).my_access, 'read');
    await query(`UPDATE grants SET permission = 'read' WHERE document_id = $1 AND grantee_id = $2`, [id, await userId('vik')]);
  });
});

describe('T-09 administrators manage the system but never read content', () => {
  test('admin cannot view or download any document', async () => {
    const c = await as('admin');
    for (const title of Object.values(DOCS)) {
      const id = await docId(title);
      assert.equal((await c.get(`/api/documents/${id}`)).status, 404);
      assert.equal((await c.get(`/api/documents/${id}/download`)).status, 404);
    }
    assert.equal((await c.get('/api/documents')).data.documents.length, 0);
  });

  test('admins cannot be added as grantees', async () => {
    const c = await as('omar');
    const r = await c.post(`/api/documents/${await docId(DOCS.ndaGlobex)}/grants`, { json: { userId: await userId('admin'), permission: 'read' } });
    assert.equal(r.status, 400);
  });
});

describe('T-10 deleted documents', () => {
  test('a grantee loses access when the owner deletes; the owner can restore', async () => {
    const id = await docId(DOCS.auditPapers);
    const omar = await as('omar');
    const olivia = await as('olivia');
    assert.equal((await olivia.get(`/api/documents/${id}/download`)).status, 200);
    assert.equal((await omar.del(`/api/documents/${id}`)).status, 200);
    assert.equal((await olivia.get(`/api/documents/${id}/download`)).status, 404);
    assert.equal((await omar.get(`/api/documents/${id}/download`)).status, 404, 'even the owner must restore before downloading');
    const trash = await omar.get('/api/documents/trash');
    assert.ok(trash.data.documents.some((d) => d.id === id));
    assert.equal((await olivia.post(`/api/documents/${id}/restore`)).status, 404, 'only the owner restores');
    assert.equal((await omar.post(`/api/documents/${id}/restore`)).status, 200);
    assert.equal((await olivia.get(`/api/documents/${id}/download`)).status, 200);
  });
});

describe('T-11 owning one document gives no power over another document\'s grants', () => {
  test('olivia cannot revoke vera\'s grant on omar\'s MSA by routing it through her own document', async () => {
    const msa = await docId(DOCS.msaAcme);
    const [vg] = await query('SELECT id FROM grants WHERE document_id = $1 AND revoked_at IS NULL', [msa]);
    const olivia = await as('olivia');
    const r = await olivia.del(`/api/documents/${await docId(DOCS.salaryVik)}/grants/${vg.id}`);
    assert.equal(r.status, 404);
    const [still] = await query('SELECT revoked_at FROM grants WHERE id = $1', [vg.id]);
    assert.equal(still.revoked_at, null);
  });
});

describe('T-12 roles', () => {
  test('a viewer cannot upload documents', async () => {
    const c = await as('vik');
    const r = await c.post('/api/documents', { form: fileForm('a.pdf', makePdf(['x']), { title: 'x', category: 'HR' }) });
    assert.equal(r.status, 403);
  });

  test('viewers can only be given read access', async () => {
    const c = await as('olivia');
    const r = await c.post(`/api/documents/${await docId(DOCS.reviewOmar)}/grants`, { json: { userId: await userId('vik'), permission: 'edit' } });
    assert.equal(r.status, 400);
  });

  test('non-admins cannot reach any admin route', async () => {
    for (const who of ['olivia', 'vik']) {
      const c = await as(who);
      for (const p of ['/api/admin/overview', '/api/admin/audit', '/api/admin/audit/verify', '/api/admin/users', '/api/admin/documents']) {
        assert.equal((await c.get(p)).status, 403, `${who} reached ${p}`);
      }
      assert.equal((await c.post('/api/admin/users', { json: { email: 'evil@x.io', name: 'E', role: 'admin', password: 'longpassword1' } })).status, 403);
    }
  });

  test('the people directory is for owners only and never lists admins', async () => {
    assert.equal((await (await as('vik')).get('/api/users/directory')).status, 403);
    const r = await (await as('olivia')).get('/api/users/directory');
    assert.ok(r.data.users.length > 0);
    assert.ok(r.data.users.every((u) => u.role !== 'admin'));
  });
});

describe('T-23 malformed ids are refused cleanly, never a 500', () => {
  test('garbage, SQL and traversal in the id slot', async () => {
    const c = await as('olivia');
    for (const bad of ['not-a-uuid', "1' OR '1'='1", '..%2F..%2Fetc%2Fpasswd', '00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-4fff-bfff-ffffffffffff']) {
      const r = await c.get(`/api/documents/${bad}/download`);
      assert.equal(r.status, 404, `${bad} -> ${r.status}`);
    }
  });
});

describe('T-25 refused attempts are recorded', () => {
  test('a denied download writes a denied audit row naming the user and document', async () => {
    const id = await docId(DOCS.ndaGlobex);
    const before = await auditCount(`action = 'document.download' AND outcome = 'denied' AND document_id = $1`, [id]);
    await (await as('vera')).get(`/api/documents/${id}/download`);
    const rows = await query(`SELECT actor_email FROM audit_log WHERE action = 'document.download' AND outcome = 'denied' AND document_id = $1 ORDER BY seq DESC LIMIT 1`, [id]);
    assert.equal(await auditCount(`action = 'document.download' AND outcome = 'denied' AND document_id = $1`, [id]), before + 1);
    assert.equal(rows[0].actor_email, 'vera.partner@trustvault.demo');
  });
});
