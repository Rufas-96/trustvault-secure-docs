// Taking access away works immediately: whatever was issued before stops working.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { as, Client, DEMO_USERS, docId, DOCS, query, start, stop, userId } from './helpers.js';

before(start);
after(stop);

describe('T-04 revoking a grant takes effect on the very next request', () => {
  test('vik downloads, olivia revokes, the same session is refused one request later', async () => {
    const id = await docId(DOCS.salaryVik);
    const vik = await as('vik');
    const olivia = await as('olivia');
    assert.equal((await vik.get(`/api/documents/${id}/download`)).status, 200);

    const grants = await olivia.get(`/api/documents/${id}/grants`);
    const live = grants.data.grants.find((g) => g.email === 'vik.viewer@trustvault.demo' && !g.revoked_at);
    assert.equal((await olivia.del(`/api/documents/${id}/grants/${live.id}`)).status, 200);

    for (const p of ['', '/download', '/download?version=1', '/versions']) {
      assert.equal((await vik.get(`/api/documents/${id}${p}`)).status, 404, `still reachable: ${p}`);
    }
    assert.ok(!(await vik.get('/api/documents')).data.documents.some((d) => d.id === id), 'still listed');

    // Re-granting restores access, and the revoked row is kept as history.
    assert.equal((await olivia.post(`/api/documents/${id}/grants`, { json: { userId: vik.user.id, permission: 'read' } })).status, 201);
    assert.equal((await vik.get(`/api/documents/${id}/download`)).status, 200);
    const [{ n }] = await query('SELECT count(*)::int AS n FROM grants WHERE document_id = $1 AND grantee_id = $2', [id, vik.user.id]);
    assert.equal(n, 2);
  });

  test('downgrading edit to read stops edits immediately', async () => {
    const id = await docId(DOCS.handbook);
    const omar = await as('omar');
    const olivia = await as('olivia');
    assert.equal((await omar.patch(`/api/documents/${id}`, { json: { description: 'edit 1' } })).status, 200);
    assert.equal((await olivia.post(`/api/documents/${id}/grants`, { json: { userId: omar.user.id, permission: 'read' } })).status, 201);
    assert.equal((await omar.patch(`/api/documents/${id}`, { json: { description: 'edit 2' } })).status, 404);
    assert.equal((await omar.get(`/api/documents/${id}/download`)).status, 200);
  });
});

describe('T-05 expired grants give no access', () => {
  test('a grant whose expiry has passed is refused even though it was never revoked', async () => {
    const id = await docId(DOCS.msaAcme);
    const vera = await as('vera');
    assert.equal((await vera.get(`/api/documents/${id}/download`)).status, 200);
    await query(`UPDATE grants SET expires_at = now() - interval '1 second' WHERE document_id = $1 AND revoked_at IS NULL`, [id]);
    assert.equal((await vera.get(`/api/documents/${id}/download`)).status, 404);
    assert.ok(!(await vera.get('/api/documents')).data.documents.some((d) => d.id === id));
    await query(`UPDATE grants SET expires_at = now() + interval '30 days' WHERE document_id = $1 AND revoked_at IS NULL`, [id]);
  });

  test('an owner cannot create a grant that is already expired', async () => {
    const olivia = await as('olivia');
    const r = await olivia.post(`/api/documents/${await docId(DOCS.reviewOmar)}/grants`, {
      json: { userId: await userId('omar'), permission: 'read', expiresAt: '2020-01-01' },
    });
    assert.equal(r.status, 400);
  });
});

describe('T-14 disabling a person ends their access at once', () => {
  test('an active session stops working the moment an admin disables the account', async () => {
    const admin = await as('admin');
    const email = `leaver-${randomUUID().slice(0, 8)}@trustvault.demo`;
    const created = await admin.post('/api/admin/users', { json: { email, name: 'Leaver', role: 'viewer', password: 'leaver-password-1' } });
    assert.equal(created.status, 201);

    const olivia = await as('olivia');
    const id = await docId(DOCS.handbook);
    await olivia.post(`/api/documents/${id}/grants`, { json: { userId: created.data.user.id, permission: 'read' } });

    const leaver = await new Client().login(email, 'leaver-password-1');
    assert.equal((await leaver.get(`/api/documents/${id}/download`)).status, 200);

    assert.equal((await admin.patch(`/api/admin/users/${created.data.user.id}`, { json: { isActive: false } })).status, 200);
    assert.equal((await leaver.get(`/api/documents/${id}/download`)).status, 401);
    assert.equal((await leaver.get('/api/me')).status, 401);
    await assert.rejects(new Client().login(email, 'leaver-password-1'));
  });

  test('a disabled user is refused even if a session row somehow survives', async () => {
    const vik = await as('vik');
    await query('UPDATE users SET is_active = false WHERE id = $1', [vik.user.id]);
    try {
      assert.equal((await vik.get('/api/documents')).status, 401);
    } finally {
      await query('UPDATE users SET is_active = true WHERE id = $1', [vik.user.id]);
    }
  });
});

describe('T-20 transferring ownership', () => {
  test('the previous owner loses access immediately and the new owner gains it', async () => {
    const admin = await as('admin');
    const email = `newowner-${randomUUID().slice(0, 8)}@trustvault.demo`;
    const created = await admin.post('/api/admin/users', { json: { email, name: 'New Owner', role: 'owner', password: 'new-owner-pass-1' } });
    const omar = await as('omar');
    const id = await docId(DOCS.ndaGlobex);
    assert.equal((await omar.get(`/api/documents/${id}/download`)).status, 200);

    assert.equal((await admin.post(`/api/admin/documents/${id}/transfer`, { json: { newOwnerId: created.data.user.id } })).status, 200);
    assert.equal((await omar.get(`/api/documents/${id}/download`)).status, 404);
    const newOwner = await new Client().login(email, 'new-owner-pass-1');
    assert.equal((await newOwner.get(`/api/documents/${id}/download`)).status, 200);
  });
});

describe('T-22 signing out kills the session token, not just the cookie', () => {
  test('replaying the old cookie after logout is refused', async () => {
    const u = DEMO_USERS.find((x) => x.key === 'vik');
    const vik = await new Client().login(u.email, u.password);
    const stolenCookie = vik.cookie;
    assert.equal((await vik.post('/api/auth/logout')).status, 200);
    const replay = new Client();
    replay.cookie = stolenCookie;
    assert.equal((await replay.get('/api/documents')).status, 401);
  });
});

describe('T-09b admin rule is enforced in the access check itself, not only at grant time', () => {
  test('a grant planted directly in the database still gives an admin nothing', async () => {
    const id = await docId(DOCS.reviewOmar);
    const adminId = await userId('admin');
    const ownerId = await userId('olivia');
    await query(`INSERT INTO grants (id, document_id, grantee_id, permission, granted_by) VALUES ($1,$2,$3,'read',$4)`, [randomUUID(), id, adminId, ownerId]);
    try {
      const admin = await as('admin');
      assert.equal((await admin.get(`/api/documents/${id}/download`)).status, 404);
    } finally {
      await query(`UPDATE grants SET revoked_at = now() WHERE document_id = $1 AND grantee_id = $2`, [id, adminId]);
    }
  });
});
