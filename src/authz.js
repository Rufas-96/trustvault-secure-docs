// ─────────────────────────────────────────────────────────────────────────────
// THE authorisation decision for documents. Every document route goes through
// requireDocAccess(); nothing else in the codebase decides who can reach a document.
//
// Permission model (also in README):
//   level      what it allows
//   ─────      ─────────────────────────────────────────────────────────────
//   read       see metadata, list versions, download any version
//   edit       read + rename / re-describe / re-categorise + upload a new version
//   owner      edit + delete / restore + grant / revoke + see the document's activity
//
//   - "owner" is never granted: it is whoever documents.owner_id points at.
//   - read/edit come only from a live row in `grants` (not revoked, not expired).
//   - Admins get NO document content access. They see metadata and the audit trail.
//   - A viewer-role user is capped at read even if an old edit grant exists.
//   - A deleted document is reachable only by its owner, and only to restore it.
//   - Anything not listed above is denied.
//
// The check runs against the database on every request. There are no cached decisions
// and no signed URLs, so a revoked grant stops working on the very next request.
// ─────────────────────────────────────────────────────────────────────────────
import { query } from './db.js';
import { audit } from './audit.js';
import { HttpError, isUuid } from './http.js';

const RANK = { read: 1, edit: 2, owner: 3 };

// action -> minimum level needed. An action missing from this table is denied.
export const ACTIONS = Object.freeze({
  view: 'read',
  download: 'read',
  'list-versions': 'read',
  edit: 'edit',
  'upload-version': 'edit',
  delete: 'owner',
  restore: 'owner',
  share: 'owner',
  'view-grants': 'owner',
  'view-activity': 'owner',
});

// Actions an owner may perform on a document that is in the trash.
const ALLOWED_WHEN_DELETED = new Set(['restore', 'view']);

/**
 * Work out what `user` may do with document `docId`.
 * Returns { doc, level } where level is 'owner' | 'edit' | 'read' | null.
 */
export async function effectiveAccess(user, docId) {
  if (!user || !user.is_active || !isUuid(docId)) return { doc: null, level: null };

  const [doc] = await query('SELECT * FROM documents WHERE id = $1', [docId]);
  if (!doc) return { doc: null, level: null };

  // Administrators manage the system, not the content.
  if (user.role === 'admin') return { doc, level: null };

  if (doc.owner_id === user.id) return { doc, level: 'owner' };

  if (doc.deleted_at) return { doc, level: null };

  const [grant] = await query(
    `SELECT permission FROM grants
      WHERE document_id = $1 AND grantee_id = $2
        AND revoked_at IS NULL
        AND (expires_at IS NULL OR expires_at > now())`,
    [docId, user.id],
  );
  if (!grant) return { doc, level: null };

  const level = user.role === 'viewer' ? 'read' : grant.permission;
  return { doc, level };
}

export function levelAllows(level, action) {
  const needed = ACTIONS[action];
  if (!needed || !level) return false;
  return RANK[level] >= RANK[needed];
}

/**
 * Throws 404 unless `user` may perform `action` on `docId`. Denials are audited.
 * 404 rather than 403 so that probing ids does not reveal which documents exist.
 */
export async function authorizeDoc(user, docId, action, ip) {
  const { doc, level } = await effectiveAccess(user, docId);
  let allowed = Boolean(doc) && levelAllows(level, action);
  if (allowed && doc.deleted_at && !ALLOWED_WHEN_DELETED.has(action)) allowed = false;

  if (!allowed) {
    await audit({
      actor: user,
      action: `document.${action}`,
      outcome: 'denied',
      documentId: doc ? doc.id : null,
      details: doc ? { reason: level ? `needs ${ACTIONS[action] ?? 'unknown'}, has ${level}` : 'no access' } : { reason: 'no such document', requestedId: String(docId).slice(0, 64) },
      ip,
    });
    throw new HttpError(404, 'Document not found');
  }
  return { doc, level };
}

/** Express middleware: requireDocAccess('download') → sets req.doc and req.docLevel. */
export function requireDocAccess(action) {
  if (!ACTIONS[action]) throw new Error(`Unknown document action: ${action}`);
  return async (req, res, next) => {
    const { doc, level } = await authorizeDoc(req.user, req.params.id, action, req.ip);
    req.doc = doc;
    req.docLevel = level;
    next();
  };
}

/** Express middleware: only users whose role is in `roles`. */
export function requireRole(...roles) {
  return async (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      await audit({ actor: req.user, action: 'role.check', outcome: 'denied', details: { needed: roles, path: req.originalUrl.slice(0, 200) }, ip: req.ip });
      throw new HttpError(403, 'You do not have permission to do that');
    }
    next();
  };
}

/**
 * SQL fragment that limits a documents query (alias d) to what user $1 can read.
 * Used by list and search so they can never return a document the user could not open.
 */
export const READABLE_BY_USER_SQL = `
  d.deleted_at IS NULL AND (
    d.owner_id = $1
    OR EXISTS (
      SELECT 1 FROM grants g
       WHERE g.document_id = d.id AND g.grantee_id = $1
         AND g.revoked_at IS NULL
         AND (g.expires_at IS NULL OR g.expires_at > now())
    )
  )`;
