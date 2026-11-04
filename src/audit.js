// Tamper-evident audit trail.
//
// Three layers protect it:
//   1. The database refuses UPDATE / DELETE / TRUNCATE on audit_log (triggers in schema.sql).
//   2. Every row carries hash = HMAC(key, prev_hash + row). Removing, reordering or editing
//      any row breaks every hash after it, and verifyChain() reports where.
//   3. The HMAC key lives in an environment variable, not the database, so someone with
//      database access alone cannot forge a consistent replacement chain.
//
// Successful changes are audited inside the same transaction as the change itself, so a
// change cannot commit without its audit row. Denials are audited in their own transaction.
import { createHmac } from 'node:crypto';
import { config } from './config.js';
import { tx, query } from './db.js';

const GENESIS = '0'.repeat(64);

function canonical(row) {
  return JSON.stringify([
    new Date(row.at).toISOString(),
    row.actor_id ?? null,
    row.actor_email ?? null,
    row.action,
    row.outcome,
    row.document_id ?? null,
    row.target_user_id ?? null,
    row.details,
    row.ip ?? null,
  ]);
}

function chainHash(prevHash, row) {
  return createHmac('sha256', config.auditHmacKey).update(prevHash).update('|').update(canonical(row)).digest('hex');
}

/**
 * Append one audit row using the given transaction's query function.
 * entry: { actor, action, outcome, documentId, targetUserId, details, ip }
 */
export async function appendAudit(q, entry) {
  // Serialise writers so two requests cannot both chain onto the same prev_hash.
  await q('SELECT pg_advisory_xact_lock(727274)');
  const [last] = await q('SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1');
  const row = {
    at: new Date(),
    actor_id: entry.actor?.id ?? null,
    actor_email: entry.actor?.email ?? entry.actorEmail ?? null,
    action: entry.action,
    outcome: entry.outcome ?? 'ok',
    document_id: entry.documentId ?? null,
    target_user_id: entry.targetUserId ?? null,
    details: JSON.stringify(entry.details ?? {}),
    ip: entry.ip ?? null,
  };
  const prevHash = last ? last.hash : GENESIS;
  const hash = chainHash(prevHash, row);
  await q(
    `INSERT INTO audit_log (at, actor_id, actor_email, action, outcome, document_id, target_user_id, details, ip, prev_hash, hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [row.at, row.actor_id, row.actor_email, row.action, row.outcome, row.document_id, row.target_user_id, row.details, row.ip, prevHash, hash],
  );
}

/** Append in a transaction of its own (used for denials and logins). */
export function audit(entry) {
  return tx((t) => appendAudit(t.query, entry));
}

/** Recompute the whole chain. Returns { ok, checked, brokenAt?, reason? }. */
export async function verifyChain() {
  const rows = await query(
    `SELECT seq, at, actor_id, actor_email, action, outcome, document_id, target_user_id, details, ip, prev_hash, hash
       FROM audit_log ORDER BY seq`,
  );
  let prev = GENESIS;
  for (const row of rows) {
    if (row.prev_hash !== prev) {
      return { ok: false, checked: rows.length, brokenAt: Number(row.seq), reason: 'previous hash does not match: a row before this one was removed or changed' };
    }
    if (chainHash(prev, row) !== row.hash) {
      return { ok: false, checked: rows.length, brokenAt: Number(row.seq), reason: 'row contents do not match its hash: this row was altered' };
    }
    prev = row.hash;
  }
  return { ok: true, checked: rows.length, head: prev };
}
