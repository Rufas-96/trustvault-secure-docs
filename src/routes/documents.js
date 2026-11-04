// Document routes. Every route with :id runs requireDocAccess(<action>) first;
// the handler itself only ever sees documents the server has already authorised.
import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import multer from 'multer';
import { config } from '../config.js';
import { query, tx } from '../db.js';
import { appendAudit } from '../audit.js';
import { READABLE_BY_USER_SQL, requireDocAccess, requireRole } from '../authz.js';
import { decryptFile, encryptFile, sha256Hex } from '../crypto.js';
import { contentDisposition, validateUpload } from '../files.js';
import { HttpError, category, isUuid, likePattern, optionalDate, str } from '../http.js';

export const documentsRouter = Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes, files: 1, fields: 10, fieldSize: 4096, parts: 12 },
}).single('file');

const DOC_COLUMNS = `
  d.id, d.title, d.description, d.category, d.current_version, d.created_at, d.updated_at, d.deleted_at,
  d.owner_id, o.name AS owner_name, o.email AS owner_email,
  v.filename, v.mime_type, v.size_bytes`;

const DOC_FROM = `
  FROM documents d
  JOIN users o ON o.id = d.owner_id
  JOIN document_versions v ON v.document_id = d.id AND v.version = d.current_version`;

async function loadDocSummary(id) {
  const [doc] = await query(`SELECT ${DOC_COLUMNS} ${DOC_FROM} WHERE d.id = $1`, [id]);
  return doc;
}

// ── List and search ──────────────────────────────────────────────────────────
// Search can only ever return documents the caller can read: the READABLE_BY_USER_SQL
// filter is always applied, and user filters are added on top of it with AND.
documentsRouter.get('/', async (req, res) => {
  const params = [req.user.id];
  const where = [READABLE_BY_USER_SQL];
  const add = (sql, value) => {
    params.push(value);
    where.push(sql.replaceAll('?', `$${params.length}`));
  };

  const q = str(req.query.q, 'q', { max: 100, optional: true });
  if (q) add(`(d.title ILIKE ? OR v.filename ILIKE ? OR d.description ILIKE ?)`, likePattern(q));
  const owner = str(req.query.owner, 'owner', { max: 100, optional: true });
  if (owner) add(`(o.name ILIKE ? OR o.email ILIKE ?)`, likePattern(owner));
  if (req.query.category) add(`d.category = ?`, category(req.query.category));
  const from = optionalDate(req.query.from, 'from');
  if (from) add(`d.created_at >= ?`, from);
  const to = optionalDate(req.query.to, 'to');
  if (to) add(`d.created_at < ?`, new Date(to.getTime() + 24 * 3600 * 1000));
  if (req.query.scope === 'mine') add(`d.owner_id = ?`, req.user.id);
  else if (req.query.scope === 'shared') add(`d.owner_id <> ?`, req.user.id);

  // Sort is chosen from a fixed map, never interpolated from the request.
  const SORTS = { newest: 'd.updated_at DESC', oldest: 'd.updated_at ASC', title: 'lower(d.title) ASC' };
  const orderBy = SORTS[req.query.sort] || SORTS.newest;

  const rows = await query(
    `SELECT ${DOC_COLUMNS},
            CASE WHEN d.owner_id = $1 THEN 'owner'
                 ELSE (SELECT g.permission FROM grants g
                        WHERE g.document_id = d.id AND g.grantee_id = $1 AND g.revoked_at IS NULL
                          AND (g.expires_at IS NULL OR g.expires_at > now()))
            END AS my_access
       ${DOC_FROM}
      WHERE ${where.join(' AND ')}
      ORDER BY ${orderBy}
      LIMIT 200`,
    params,
  );
  // Viewers are capped at read regardless of what an old grant row says.
  if (req.user.role === 'viewer') for (const r of rows) if (r.my_access === 'edit') r.my_access = 'read';
  res.json({ documents: rows });
});

// Trash: the caller's own deleted documents.
documentsRouter.get('/trash', requireRole('owner'), async (req, res) => {
  const rows = await query(
    `SELECT ${DOC_COLUMNS} ${DOC_FROM} WHERE d.owner_id = $1 AND d.deleted_at IS NOT NULL ORDER BY d.deleted_at DESC`,
    [req.user.id],
  );
  res.json({ documents: rows });
});

// ── Create ───────────────────────────────────────────────────────────────────
// Role is checked BEFORE multer reads the body, so viewers cannot make us buffer a file.
documentsRouter.post('/', requireRole('owner'), upload, async (req, res) => {
  const title = str(req.body.title, 'Title', { min: 1, max: 150 });
  const description = str(req.body.description, 'Description', { max: 1000 });
  const cat = category(req.body.category);
  const { filename, mime } = validateUpload(req.file, config.maxUploadBytes);

  const id = randomUUID();
  const enc = encryptFile(req.file.buffer, `${id}:1`);
  await tx(async ({ query: q }) => {
    await q(`INSERT INTO documents (id, owner_id, title, description, category) VALUES ($1,$2,$3,$4,$5)`, [
      id, req.user.id, title, description, cat,
    ]);
    await q(
      `INSERT INTO document_versions (id, document_id, version, filename, mime_type, size_bytes, sha256, iv, auth_tag, ciphertext, uploaded_by)
       VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [randomUUID(), id, filename, mime, req.file.size, sha256Hex(req.file.buffer), enc.iv, enc.authTag, enc.ciphertext, req.user.id],
    );
    await appendAudit(q, {
      actor: req.user, action: 'document.upload', documentId: id, ip: req.ip,
      details: { title, filename, size: req.file.size, sha256: sha256Hex(req.file.buffer), version: 1 },
    });
  });
  res.status(201).json({ document: await loadDocSummary(id) });
});

// ── Read ─────────────────────────────────────────────────────────────────────
documentsRouter.get('/:id', requireDocAccess('view'), async (req, res) => {
  const doc = await loadDocSummary(req.doc.id);
  res.json({ document: doc, myAccess: req.docLevel });
});

documentsRouter.get('/:id/versions', requireDocAccess('list-versions'), async (req, res) => {
  const versions = await query(
    `SELECT v.version, v.filename, v.mime_type, v.size_bytes, v.sha256, v.created_at, u.name AS uploaded_by_name
       FROM document_versions v JOIN users u ON u.id = v.uploaded_by
      WHERE v.document_id = $1 ORDER BY v.version DESC`,
    [req.doc.id],
  );
  res.json({ versions });
});

documentsRouter.get('/:id/download', requireDocAccess('download'), async (req, res) => {
  let version = req.doc.current_version;
  if (req.query.version !== undefined) {
    version = Number(req.query.version);
    if (!Number.isInteger(version) || version < 1) throw new HttpError(400, 'version must be a positive whole number');
  }
  const [file] = await query(
    `SELECT version, filename, mime_type, size_bytes, sha256, iv, auth_tag, ciphertext
       FROM document_versions WHERE document_id = $1 AND version = $2`,
    [req.doc.id, version],
  );
  if (!file) throw new HttpError(404, 'That version does not exist');

  const plaintext = decryptFile({ iv: file.iv, ciphertext: file.ciphertext, authTag: file.auth_tag }, `${req.doc.id}:${file.version}`);
  if (sha256Hex(plaintext) !== file.sha256) throw new HttpError(500, 'Stored file failed its integrity check');

  // Audit first. If the audit write fails, the file is not sent.
  await tx(({ query: q }) =>
    appendAudit(q, {
      actor: req.user, action: 'document.download', documentId: req.doc.id, ip: req.ip,
      details: { version: file.version, filename: file.filename, access: req.docLevel },
    }),
  );

  res.set({
    'Content-Type': file.mime_type,
    'Content-Length': String(plaintext.length),
    'Content-Disposition': contentDisposition(file.filename),
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'Cache-Control': 'no-store, private',
  });
  res.end(plaintext);
});

// ── Edit ─────────────────────────────────────────────────────────────────────
documentsRouter.patch('/:id', requireDocAccess('edit'), async (req, res) => {
  const changes = {};
  if (req.body?.title !== undefined) changes.title = str(req.body.title, 'Title', { min: 1, max: 150 });
  if (req.body?.description !== undefined) changes.description = str(req.body.description, 'Description', { max: 1000 });
  if (req.body?.category !== undefined) changes.category = category(req.body.category);
  if (Object.keys(changes).length === 0) throw new HttpError(400, 'Nothing to change');

  const before = Object.fromEntries(Object.keys(changes).map((k) => [k, req.doc[k]]));
  await tx(async ({ query: q }) => {
    await q(
      `UPDATE documents SET title = COALESCE($2, title), description = COALESCE($3, description),
              category = COALESCE($4, category), updated_at = now() WHERE id = $1`,
      [req.doc.id, changes.title ?? null, changes.description ?? null, changes.category ?? null],
    );
    await appendAudit(q, { actor: req.user, action: 'document.edit', documentId: req.doc.id, ip: req.ip, details: { before, after: changes } });
  });
  res.json({ document: await loadDocSummary(req.doc.id) });
});

// Authorisation runs BEFORE multer, so someone without edit access is refused before
// their upload body is even read.
documentsRouter.post('/:id/versions', requireDocAccess('upload-version'), upload, async (req, res) => {
  const { filename, mime } = validateUpload(req.file, config.maxUploadBytes);
  const sha = sha256Hex(req.file.buffer);
  await tx(async ({ query: q }) => {
    // Lock the document row so two simultaneous uploads cannot both claim version N+1.
    const [row] = await q('SELECT current_version FROM documents WHERE id = $1 FOR UPDATE', [req.doc.id]);
    const version = row.current_version + 1;
    const enc = encryptFile(req.file.buffer, `${req.doc.id}:${version}`);
    await q(
      `INSERT INTO document_versions (id, document_id, version, filename, mime_type, size_bytes, sha256, iv, auth_tag, ciphertext, uploaded_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [randomUUID(), req.doc.id, version, filename, mime, req.file.size, sha, enc.iv, enc.authTag, enc.ciphertext, req.user.id],
    );
    await q('UPDATE documents SET current_version = $2, updated_at = now() WHERE id = $1', [req.doc.id, version]);
    await appendAudit(q, {
      actor: req.user, action: 'document.new_version', documentId: req.doc.id, ip: req.ip,
      details: { version, filename, size: req.file.size, sha256: sha },
    });
  });
  res.status(201).json({ document: await loadDocSummary(req.doc.id) });
});

// ── Delete and restore (soft delete; versions are kept) ─────────────────────
documentsRouter.delete('/:id', requireDocAccess('delete'), async (req, res) => {
  await tx(async ({ query: q }) => {
    await q('UPDATE documents SET deleted_at = now(), deleted_by = $2 WHERE id = $1', [req.doc.id, req.user.id]);
    await appendAudit(q, { actor: req.user, action: 'document.delete', documentId: req.doc.id, ip: req.ip, details: { title: req.doc.title } });
  });
  res.json({ ok: true });
});

documentsRouter.post('/:id/restore', requireDocAccess('restore'), async (req, res) => {
  if (!req.doc.deleted_at) throw new HttpError(400, 'Document is not in the trash');
  await tx(async ({ query: q }) => {
    await q('UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = now() WHERE id = $1', [req.doc.id]);
    await appendAudit(q, { actor: req.user, action: 'document.restore', documentId: req.doc.id, ip: req.ip, details: { title: req.doc.title } });
  });
  res.json({ document: await loadDocSummary(req.doc.id) });
});

// ── Sharing ──────────────────────────────────────────────────────────────────
documentsRouter.get('/:id/grants', requireDocAccess('view-grants'), async (req, res) => {
  const grants = await query(
    `SELECT g.id, g.permission, g.created_at, g.expires_at, g.revoked_at,
            u.id AS user_id, u.name, u.email, u.role, u.is_active,
            gb.name AS granted_by_name, rb.name AS revoked_by_name
       FROM grants g
       JOIN users u ON u.id = g.grantee_id
       JOIN users gb ON gb.id = g.granted_by
       LEFT JOIN users rb ON rb.id = g.revoked_by
      WHERE g.document_id = $1
      ORDER BY (g.revoked_at IS NULL) DESC, g.created_at DESC`,
    [req.doc.id],
  );
  res.json({ grants });
});

documentsRouter.post('/:id/grants', requireDocAccess('share'), async (req, res) => {
  const { userId, permission } = req.body ?? {};
  if (!isUuid(userId)) throw new HttpError(400, 'Choose a person to share with');
  if (permission !== 'read' && permission !== 'edit') throw new HttpError(400, 'permission must be read or edit');
  const expiresAt = optionalDate(req.body.expiresAt, 'expiresAt');
  if (expiresAt && expiresAt.getTime() <= Date.now()) throw new HttpError(400, 'Expiry must be in the future');
  if (expiresAt && expiresAt.getTime() > Date.now() + 366 * 24 * 3600 * 1000) throw new HttpError(400, 'Expiry can be at most one year away');

  const [grantee] = await query('SELECT id, name, email, role, is_active FROM users WHERE id = $1', [userId]);
  if (!grantee || !grantee.is_active) throw new HttpError(400, 'That person does not exist or is disabled');
  if (grantee.id === req.doc.owner_id) throw new HttpError(400, 'The owner already has full access');
  if (grantee.role === 'admin') throw new HttpError(400, 'Administrators cannot be given document access');
  if (grantee.role === 'viewer' && permission === 'edit') throw new HttpError(400, 'Viewers can only be given read access');

  const grant = await tx(async ({ query: q }) => {
    // Replacing a live grant (e.g. read -> edit) revokes the old row and writes a new one,
    // so the history of every permission level anyone ever held is preserved.
    const [existing] = await q(
      `UPDATE grants SET revoked_at = now(), revoked_by = $3
        WHERE document_id = $1 AND grantee_id = $2 AND revoked_at IS NULL
      RETURNING permission, expires_at`,
      [req.doc.id, grantee.id, req.user.id],
    );
    const id = randomUUID();
    await q(
      `INSERT INTO grants (id, document_id, grantee_id, permission, granted_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, req.doc.id, grantee.id, permission, req.user.id, expiresAt],
    );
    await appendAudit(q, {
      actor: req.user, action: existing ? 'permission.change' : 'permission.grant', documentId: req.doc.id,
      targetUserId: grantee.id, ip: req.ip,
      details: { grantee: grantee.email, permission, expiresAt, previous: existing?.permission ?? null },
    });
    return { id, permission, expires_at: expiresAt };
  });
  res.status(201).json({ grant });
});

documentsRouter.delete('/:id/grants/:grantId', requireDocAccess('share'), async (req, res) => {
  if (!isUuid(req.params.grantId)) throw new HttpError(404, 'Grant not found');
  await tx(async ({ query: q }) => {
    // document_id is part of the WHERE: a grant id from a different document is "not found",
    // so owning document A never lets you revoke grants on document B.
    const [g] = await q(
      `UPDATE grants SET revoked_at = now(), revoked_by = $3
        WHERE id = $1 AND document_id = $2 AND revoked_at IS NULL
      RETURNING grantee_id, permission`,
      [req.params.grantId, req.doc.id, req.user.id],
    );
    if (!g) throw new HttpError(404, 'Grant not found or already revoked');
    // Revocation is immediate because every request re-checks grants in the database.
    await appendAudit(q, {
      actor: req.user, action: 'permission.revoke', documentId: req.doc.id, targetUserId: g.grantee_id, ip: req.ip,
      details: { permission: g.permission },
    });
  });
  res.json({ ok: true });
});

// The owner can see everything that happened to their document, including refusals.
documentsRouter.get('/:id/activity', requireDocAccess('view-activity'), async (req, res) => {
  const rows = await query(
    `SELECT a.seq, a.at, a.actor_email, a.action, a.outcome, a.details, a.ip, t.email AS target_email
       FROM audit_log a LEFT JOIN users t ON t.id = a.target_user_id
      WHERE a.document_id = $1 ORDER BY a.seq DESC LIMIT 200`,
    [req.doc.id],
  );
  res.json({ activity: rows.map((r) => ({ ...r, seq: Number(r.seq), details: JSON.parse(r.details) })) });
});
