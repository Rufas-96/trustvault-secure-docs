// The audit trail records every access decision and cannot be quietly altered.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { as, auditCount, docId, DOCS, fileForm, makePdf, query, start, stop } from './helpers.js';
import { verifyChain } from '../src/audit.js';

before(start);
after(stop);

describe('T-15 every kind of event the brief asks for is recorded', () => {
  test('upload, download, change, new version, permission grant/change/revoke, delete, restore', async () => {
    const olivia = await as('olivia');
    const omar = await as('omar');
    const created = await olivia.post('/api/documents', { form: fileForm('offer.pdf', makePdf(['Offer letter']), { title: 'Offer letter', category: 'HR' }) });
    assert.equal(created.status, 201);
    const id = created.data.document.id;

    await olivia.get(`/api/documents/${id}/download`);
    await olivia.patch(`/api/documents/${id}`, { json: { title: 'Offer letter (final)' } });
    await olivia.post(`/api/documents/${id}/versions`, { form: fileForm('offer-v2.pdf', makePdf(['v2'])) });
    await olivia.post(`/api/documents/${id}/grants`, { json: { userId: omar.user.id, permission: 'read' } });
    await olivia.post(`/api/documents/${id}/grants`, { json: { userId: omar.user.id, permission: 'edit' } });
    const g = (await olivia.get(`/api/documents/${id}/grants`)).data.grants.find((x) => !x.revoked_at);
    await olivia.del(`/api/documents/${id}/grants/${g.id}`);
    await olivia.del(`/api/documents/${id}`);
    await olivia.post(`/api/documents/${id}/restore`);

    const rows = await query('SELECT action, outcome, actor_email FROM audit_log WHERE document_id = $1 ORDER BY seq', [id]);
    assert.deepEqual(rows.map((r) => r.action), [
      'document.upload', 'document.download', 'document.edit', 'document.new_version',
      'permission.grant', 'permission.change', 'permission.revoke', 'document.delete', 'document.restore',
    ]);
    assert.ok(rows.every((r) => r.outcome === 'ok' && r.actor_email === 'olivia.owner@trustvault.demo'));
  });

  test('sign-ins, failed sign-ins and refused admin access are recorded', async () => {
    const before = await auditCount(`action = 'auth.login' AND outcome = 'denied'`);
    const r = await fetch(`${(await import('./helpers.js')).baseUrl}/api/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'vik.viewer@trustvault.demo', password: 'wrong' }),
    });
    assert.equal(r.status, 401);
    assert.equal(await auditCount(`action = 'auth.login' AND outcome = 'denied'`), before + 1);
    await (await as('vik')).get('/api/admin/audit');
    assert.ok((await auditCount(`action = 'role.check' AND outcome = 'denied' AND actor_email = 'vik.viewer@trustvault.demo'`)) >= 1);
  });
});

describe('T-16 the audit log cannot be altered through the database', () => {
  test('UPDATE, DELETE and TRUNCATE on audit_log are rejected', async () => {
    await assert.rejects(query(`UPDATE audit_log SET actor_email = 'someone-else@x.io'`), /append-only/);
    await assert.rejects(query(`DELETE FROM audit_log WHERE action = 'document.download'`), /append-only/);
    await assert.rejects(query('TRUNCATE audit_log'), /append-only/);
  });

  test('the HMAC chain verifies, and detects an edit made by someone who disabled the triggers', async () => {
    assert.equal((await verifyChain()).ok, true);
    // A database owner CAN disable triggers. This is exactly why the HMAC chain exists.
    const [row] = await query(`SELECT seq, actor_email FROM audit_log WHERE action = 'document.download' ORDER BY seq LIMIT 1`);
    await query('ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update');
    try {
      await query(`UPDATE audit_log SET actor_email = 'innocent@trustvault.demo' WHERE seq = $1`, [row.seq]);
      const result = await verifyChain();
      assert.equal(result.ok, false);
      assert.equal(result.brokenAt, Number(row.seq));
      assert.match(result.reason, /altered/);

      // Admins see it on the overview as a critical alert.
      const overview = await (await as('admin')).get('/api/admin/overview');
      assert.equal(overview.data.alerts[0].kind, 'audit-tampered');
    } finally {
      await query(`UPDATE audit_log SET actor_email = $2 WHERE seq = $1`, [row.seq, row.actor_email]);
      await query('ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update');
    }
    assert.equal((await verifyChain()).ok, true, 'restoring the original value restores the chain');
  });
});

describe('T-17 deleting an audit row is detected', () => {
  test('removing a row breaks the chain at the row after it', async () => {
    const [victim] = await query(`SELECT * FROM audit_log WHERE action = 'document.download' ORDER BY seq LIMIT 1`);
    const [next] = await query('SELECT seq FROM audit_log WHERE seq > $1 ORDER BY seq LIMIT 1', [victim.seq]);
    await query('ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update');
    try {
      await query('DELETE FROM audit_log WHERE seq = $1', [victim.seq]);
      const result = await verifyChain();
      assert.equal(result.ok, false);
      assert.equal(result.brokenAt, Number(next.seq));
      assert.match(result.reason, /removed or changed/);
    } finally {
      await query(
        `INSERT INTO audit_log (seq, at, actor_id, actor_email, action, outcome, document_id, target_user_id, details, ip, prev_hash, hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [victim.seq, victim.at, victim.actor_id, victim.actor_email, victim.action, victim.outcome, victim.document_id, victim.target_user_id, victim.details, victim.ip, victim.prev_hash, victim.hash],
      );
      await query('ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update');
    }
    assert.equal((await verifyChain()).ok, true);
  });

  test('a forged row computed without the HMAC key is detected', async () => {
    const { createHash } = await import('node:crypto');
    const [last] = await query('SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1');
    // An attacker with SQL access appends an innocent-looking row but cannot compute the
    // HMAC because the key is not in the database. A plain SHA-256 is the best they can do.
    const fake = createHash('sha256').update(last.hash + 'forged').digest('hex');
    await query(
      `INSERT INTO audit_log (at, actor_email, action, outcome, details, prev_hash, hash) VALUES (now(), 'admin@trustvault.demo', 'document.download', 'ok', '{}', $1, $2)`,
      [last.hash, fake],
    );
    const result = await verifyChain();
    assert.equal(result.ok, false);
    assert.match(result.reason, /altered/);
  });
});

describe('T-18 the owner sees the history of their own document, others do not', () => {
  test('owner activity includes refusals by other people', async () => {
    const id = await docId(DOCS.ndaGlobex);
    await (await as('vera')).get(`/api/documents/${id}/download`);
    const activity = await (await as('omar')).get(`/api/documents/${id}/activity`);
    assert.equal(activity.status, 200);
    assert.ok(activity.data.activity.some((a) => a.outcome === 'denied' && a.actor_email === 'vera.partner@trustvault.demo'));
  });
});
