// Administrator routes. Admins manage people and watch activity; they never receive
// document content (authz.js gives the admin role no document access level at all).
import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { query, tx } from '../db.js';
import { appendAudit, verifyChain } from '../audit.js';
import { requireRole } from '../authz.js';
import { hashPassword } from '../crypto.js';
import { HttpError, isUuid, likePattern, str } from '../http.js';
import { publicUser } from '../auth.js';
import { assertStrongPassword } from '../passwords.js';

export const adminRouter = Router();
adminRouter.use(requireRole('admin'));

const ROLES = ['admin', 'owner', 'viewer'];

// ── Overview: numbers and the things worth noticing ──────────────────────────
adminRouter.get('/overview', async (req, res) => {
  const [counts] = await query(`
    SELECT
      (SELECT count(*)::int FROM users WHERE is_active) AS active_users,
      (SELECT count(*)::int FROM documents WHERE deleted_at IS NULL) AS documents,
      (SELECT count(*)::int FROM grants WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())) AS live_grants,
      (SELECT count(*)::int FROM audit_log WHERE action = 'document.download' AND outcome = 'ok' AND at > now() - interval '24 hours') AS downloads_24h,
      (SELECT count(*)::int FROM audit_log WHERE outcome = 'denied' AND at > now() - interval '24 hours') AS denied_24h`);

  // Alerts: patterns an administrator should look at, not just raw counts.
  const alerts = [];
  const probers = await query(`
    SELECT actor_email, count(*)::int AS n FROM audit_log
     WHERE outcome = 'denied' AND action LIKE 'document.%' AND at > now() - interval '24 hours' AND actor_email IS NOT NULL
     GROUP BY actor_email HAVING count(*) >= 5 ORDER BY n DESC LIMIT 10`);
  for (const p of probers) alerts.push({ level: 'high', kind: 'probing', text: `${p.actor_email} was refused access to documents ${p.n} times in 24 hours` });

  const bulk = await query(`
    SELECT actor_email, count(*)::int AS n FROM audit_log
     WHERE action = 'document.download' AND outcome = 'ok' AND at > now() - interval '1 hour'
     GROUP BY actor_email HAVING count(*) >= 20 ORDER BY n DESC LIMIT 10`);
  for (const b of bulk) alerts.push({ level: 'high', kind: 'bulk-download', text: `${b.actor_email} downloaded ${b.n} files in the last hour` });

  const failedLogins = await query(`
    SELECT actor_email, count(*)::int AS n FROM audit_log
     WHERE action = 'auth.login' AND outcome = 'denied' AND at > now() - interval '24 hours'
     GROUP BY actor_email HAVING count(*) >= 5 ORDER BY n DESC LIMIT 10`);
  for (const f of failedLogins) alerts.push({ level: 'medium', kind: 'failed-logins', text: `${f.n} failed sign-ins for ${f.actor_email} in 24 hours` });

  const disabledWithGrants = await query(`
    SELECT u.email, count(*)::int AS n FROM grants g JOIN users u ON u.id = g.grantee_id
     WHERE NOT u.is_active AND g.revoked_at IS NULL GROUP BY u.email`);
  for (const d of disabledWithGrants) alerts.push({ level: 'low', kind: 'stale-grants', text: `Disabled account ${d.email} still holds ${d.n} grant(s). They cannot be used, but owners may want to revoke them.` });

  const orphaned = await query(`
    SELECT count(*)::int AS n FROM documents d JOIN users u ON u.id = d.owner_id WHERE NOT u.is_active AND d.deleted_at IS NULL`);
  if (orphaned[0].n > 0) alerts.push({ level: 'medium', kind: 'orphaned', text: `${orphaned[0].n} document(s) belong to disabled accounts. Transfer them to a new owner.` });

  const chain = await verifyChain();
  if (!chain.ok) alerts.unshift({ level: 'critical', kind: 'audit-tampered', text: `Audit chain broken at entry #${chain.brokenAt}: ${chain.reason}` });

  res.json({ counts, alerts, chain });
});

// ── Audit trail ──────────────────────────────────────────────────────────────
adminRouter.get('/audit', async (req, res) => {
  const params = [];
  const where = [];
  const add = (sql, v) => {
    params.push(v);
    where.push(sql.replaceAll('?', `$${params.length}`));
  };
  if (req.query.outcome && ['ok', 'denied', 'error'].includes(req.query.outcome)) add('a.outcome = ?', req.query.outcome);
  const action = str(req.query.action, 'action', { max: 60, optional: true });
  if (action) add('a.action ILIKE ?', likePattern(action));
  const actor = str(req.query.actor, 'actor', { max: 100, optional: true });
  if (actor) add('a.actor_email ILIKE ?', likePattern(actor));
  if (req.query.document) {
    if (!isUuid(req.query.document)) throw new HttpError(400, 'document must be a document id');
    add('a.document_id = ?', req.query.document);
  }
  if (req.query.before) {
    const before = Number(req.query.before);
    if (!Number.isInteger(before) || before < 1) throw new HttpError(400, 'before must be an entry number');
    add('a.seq < ?', before);
  }
  const rows = await query(
    `SELECT a.seq, a.at, a.actor_email, a.action, a.outcome, a.document_id, a.details, a.ip, a.hash,
            d.title AS document_title, t.email AS target_email
       FROM audit_log a
       LEFT JOIN documents d ON d.id = a.document_id
       LEFT JOIN users t ON t.id = a.target_user_id
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY a.seq DESC LIMIT 100`,
    params,
  );
  res.json({ entries: rows.map((r) => ({ ...r, seq: Number(r.seq), details: JSON.parse(r.details) })) });
});

adminRouter.get('/audit/verify', async (req, res) => {
  res.json(await verifyChain());
});

// ── Documents (metadata only) ────────────────────────────────────────────────
adminRouter.get('/documents', async (req, res) => {
  const rows = await query(`
    SELECT d.id, d.title, d.category, d.created_at, d.updated_at, d.deleted_at, d.current_version,
           o.name AS owner_name, o.email AS owner_email, o.is_active AS owner_active,
           (SELECT count(*)::int FROM grants g WHERE g.document_id = d.id AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at > now())) AS live_grants,
           (SELECT count(*)::int FROM audit_log a WHERE a.document_id = d.id AND a.action = 'document.download' AND a.outcome = 'ok') AS downloads,
           (SELECT count(*)::int FROM audit_log a WHERE a.document_id = d.id AND a.outcome = 'denied') AS denials
      FROM documents d JOIN users o ON o.id = d.owner_id
     ORDER BY d.updated_at DESC LIMIT 500`);
  res.json({ documents: rows });
});

// When someone leaves, their documents need a new owner. The old owner loses access
// immediately because access is computed from documents.owner_id on every request.
adminRouter.post('/documents/:id/transfer', async (req, res) => {
  if (!isUuid(req.params.id) || !isUuid(req.body?.newOwnerId)) throw new HttpError(400, 'Choose a document and a new owner');
  const [doc] = await query('SELECT id, owner_id, title FROM documents WHERE id = $1', [req.params.id]);
  if (!doc) throw new HttpError(404, 'Document not found');
  const [newOwner] = await query('SELECT id, email, role, is_active FROM users WHERE id = $1', [req.body.newOwnerId]);
  if (!newOwner || !newOwner.is_active || newOwner.role !== 'owner') throw new HttpError(400, 'The new owner must be an active user with the owner role');
  if (newOwner.id === doc.owner_id) throw new HttpError(400, 'That person already owns this document');

  await tx(async ({ query: q }) => {
    // The new owner's own grant (if any) is now redundant; close it so the history is clean.
    await q(`UPDATE grants SET revoked_at = now(), revoked_by = $3 WHERE document_id = $1 AND grantee_id = $2 AND revoked_at IS NULL`, [doc.id, newOwner.id, req.user.id]);
    await q('UPDATE documents SET owner_id = $2, updated_at = now() WHERE id = $1', [doc.id, newOwner.id]);
    await appendAudit(q, {
      actor: req.user, action: 'document.transfer', documentId: doc.id, targetUserId: newOwner.id, ip: req.ip,
      details: { from: doc.owner_id, to: newOwner.email, title: doc.title },
    });
  });
  res.json({ ok: true });
});

// ── Users ────────────────────────────────────────────────────────────────────
adminRouter.get('/users', async (req, res) => {
  const rows = await query(`
    SELECT u.id, u.email, u.name, u.role, u.department, u.is_active, u.is_demo, u.created_at, u.mfa_enabled, u.must_change_password,
           (SELECT count(*)::int FROM documents d WHERE d.owner_id = u.id AND d.deleted_at IS NULL) AS owned_documents,
           (SELECT count(*)::int FROM grants g WHERE g.grantee_id = u.id AND g.revoked_at IS NULL) AS live_grants,
           (SELECT count(*)::int FROM sessions s WHERE s.user_id = u.id AND s.expires_at > now()) AS sessions
      FROM users u ORDER BY u.role, u.name`);
  res.json({ users: rows });
});

adminRouter.post('/users', async (req, res) => {
  const email = str(req.body?.email, 'Email', { min: 3, max: 254 }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'Email is not valid');
  const name = str(req.body?.name, 'Name', { min: 1, max: 100 });
  const department = str(req.body?.department, 'Department', { max: 60 });
  const role = req.body?.role;
  if (!ROLES.includes(role)) throw new HttpError(400, 'Role must be admin, owner or viewer');
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  assertStrongPassword(password, { email, name });

  const [exists] = await query('SELECT 1 FROM users WHERE email = $1', [email]);
  if (exists) throw new HttpError(409, 'A user with that email already exists');
  const id = randomUUID();
  const hash = await hashPassword(password);
  await tx(async ({ query: q }) => {
    // The admin knows this initial password, so the person must replace it at first sign-in.
    await q(`INSERT INTO users (id, email, name, role, department, password_hash, must_change_password) VALUES ($1,$2,$3,$4,$5,$6,true)`, [id, email, name, role, department, hash]);
    await appendAudit(q, { actor: req.user, action: 'user.create', targetUserId: id, ip: req.ip, details: { email, role } });
  });
  res.status(201).json({ user: publicUser({ id, email, name, role, department }) });
});

async function loadManageableUser(req) {
  if (!isUuid(req.params.id)) throw new HttpError(404, 'User not found');
  if (req.params.id === req.user.id) throw new HttpError(400, 'Use your own Account page for your own account');
  const [target] = await query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  if (!target) throw new HttpError(404, 'User not found');
  if (target.is_demo) throw new HttpError(400, 'The published demo accounts are protected so evaluators cannot lock each other out. Create a new user to try this.');
  return target;
}

// Forgotten password: the admin sets a temporary one, which must be changed at next sign-in.
adminRouter.post('/users/:id/reset-password', async (req, res) => {
  const target = await loadManageableUser(req);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  assertStrongPassword(password, target);
  const hash = await hashPassword(password);
  await tx(async ({ query: q }) => {
    await q('UPDATE users SET password_hash = $2, must_change_password = true, password_changed_at = now() WHERE id = $1', [target.id, hash]);
    await q('DELETE FROM sessions WHERE user_id = $1', [target.id]);
    await appendAudit(q, { actor: req.user, action: 'user.password_reset', targetUserId: target.id, ip: req.ip, details: { email: target.email } });
  });
  res.json({ ok: true });
});

// Lost phone: clear two-factor so the person can enrol again. Ends their sessions.
adminRouter.post('/users/:id/reset-mfa', async (req, res) => {
  const target = await loadManageableUser(req);
  await tx(async ({ query: q }) => {
    await q('UPDATE users SET mfa_enabled = false, mfa_secret_enc = NULL WHERE id = $1', [target.id]);
    await q('DELETE FROM mfa_recovery_codes WHERE user_id = $1', [target.id]);
    await q('DELETE FROM sessions WHERE user_id = $1', [target.id]);
    await appendAudit(q, { actor: req.user, action: 'user.mfa_reset', targetUserId: target.id, ip: req.ip, details: { email: target.email } });
  });
  res.json({ ok: true });
});

// Enable / disable a user, or change their role.
adminRouter.patch('/users/:id', async (req, res) => {
  if (!isUuid(req.params.id)) throw new HttpError(404, 'User not found');
  if (req.params.id === req.user.id) throw new HttpError(400, 'You cannot change your own account here');
  const [target] = await query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  if (!target) throw new HttpError(404, 'User not found');

  const { isActive, role } = req.body ?? {};
  if (isActive === undefined && role === undefined) throw new HttpError(400, 'Nothing to change');
  if (isActive !== undefined && typeof isActive !== 'boolean') throw new HttpError(400, 'isActive must be true or false');
  if (role !== undefined && !ROLES.includes(role)) throw new HttpError(400, 'Role must be admin, owner or viewer');
  if (target.is_demo) throw new HttpError(400, 'The published demo accounts are protected so evaluators cannot lock each other out. Create a new user to try this.');

  if (role !== undefined && role !== target.role) {
    const [owned] = await query('SELECT count(*)::int AS n FROM documents WHERE owner_id = $1', [target.id]);
    if (owned.n > 0) throw new HttpError(400, `This user owns ${owned.n} document(s). Transfer them before changing the role.`);
  }

  await tx(async ({ query: q }) => {
    if (isActive !== undefined && isActive !== target.is_active) {
      await q('UPDATE users SET is_active = $2 WHERE id = $1', [target.id, isActive]);
      // Disabling ends every session at once; loadSession also re-checks is_active on each request.
      if (!isActive) await q('DELETE FROM sessions WHERE user_id = $1', [target.id]);
      await appendAudit(q, { actor: req.user, action: isActive ? 'user.enable' : 'user.disable', targetUserId: target.id, ip: req.ip, details: { email: target.email } });
    }
    if (role !== undefined && role !== target.role) {
      await q('UPDATE users SET role = $2 WHERE id = $1', [target.id, role]);
      // A new role means new rules: end sessions so nothing carries over from the old role.
      await q('DELETE FROM sessions WHERE user_id = $1', [target.id]);
      await appendAudit(q, { actor: req.user, action: 'user.role_change', targetUserId: target.id, ip: req.ip, details: { email: target.email, from: target.role, to: role } });
    }
  });
  const [updated] = await query('SELECT id, email, name, role, department, is_active FROM users WHERE id = $1', [target.id]);
  res.json({ user: updated });
});
