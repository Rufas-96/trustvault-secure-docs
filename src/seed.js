// Demo data: one account per role (plus a second owner and an external viewer) and a
// handful of documents with grants that exercise the permission model.
// Runs only when the users table is empty, so it never overwrites real data.
import { randomUUID } from 'node:crypto';
import { query, tx } from './db.js';
import { appendAudit } from './audit.js';
import { encryptFile, hashPassword, sha256Hex } from './crypto.js';

export const DEMO_USERS = [
  { key: 'admin', email: 'admin@trustvault.demo', name: 'Ava Administrator', role: 'admin', department: 'IT Security', password: 'Admin#Vault2026' },
  { key: 'olivia', email: 'olivia.owner@trustvault.demo', name: 'Olivia Hart', role: 'owner', department: 'Human Resources', password: 'Owner#Vault2026' },
  { key: 'omar', email: 'omar.owner@trustvault.demo', name: 'Omar Lewis', role: 'owner', department: 'Legal', password: 'Owner2#Vault2026' },
  { key: 'vik', email: 'vik.viewer@trustvault.demo', name: 'Vik Varma', role: 'viewer', department: 'Engineering', password: 'Viewer#Vault2026' },
  { key: 'vera', email: 'vera.partner@trustvault.demo', name: 'Vera Patel (Partner)', role: 'viewer', department: 'External: Acme Corp', password: 'Partner#Vault2026' },
];

/** A tiny but valid one-page PDF containing the given lines of text. */
export function makePdf(lines) {
  const esc = (s) => s.replace(/[\\()]/g, (c) => `\\${c}`);
  const text = lines.map((l, i) => `BT /F1 ${i === 0 ? 18 : 11} Tf 60 ${760 - i * 22} Td (${esc(l)}) Tj ET`).join('\n');
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${Buffer.byteLength(text)} >>\nstream\n${text}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let out = '%PDF-1.4\n';
  const offsets = [];
  objects.forEach((o, i) => {
    offsets.push(Buffer.byteLength(out));
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = Buffer.byteLength(out);
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

const DEMO_DOCS = [
  { owner: 'olivia', title: 'Salary letter: Vik Varma', category: 'HR', description: 'Annual compensation letter for 2026. Confidential to the employee.', filename: 'salary-letter-vik-varma.pdf',
    body: ['Salary letter: Vik Varma', 'Effective 1 April 2026', 'Base salary: INR 14,40,000 per year', 'This letter is confidential to the named employee.'],
    grants: [{ to: 'vik', permission: 'read' }] },
  { owner: 'olivia', title: 'Employee handbook 2026', category: 'HR', description: 'Policies every employee should know.', filename: 'employee-handbook-2026.pdf',
    body: ['Employee handbook 2026', '1. Working hours', '2. Leave policy', '3. Code of conduct', '4. Information security'],
    grants: [{ to: 'vik', permission: 'read' }, { to: 'omar', permission: 'edit' }] },
  { owner: 'olivia', title: 'Performance review: Omar Lewis', category: 'HR', description: 'Private HR record. Not shared with anyone.', filename: 'performance-review-omar.pdf',
    body: ['Performance review: Omar Lewis', 'Rating: Exceeds expectations', 'Private HR record.'], grants: [] },
  { owner: 'omar', title: 'Master services agreement: Acme Corp', category: 'Legal', description: 'Signed MSA with our partner Acme. Shared with Acme for 30 days.', filename: 'msa-acme-corp.pdf',
    body: ['Master Services Agreement', 'Between TrustVault Demo Ltd and Acme Corp', 'Term: 24 months', 'Fees: as per Schedule B'],
    grants: [{ to: 'vera', permission: 'read', days: 30 }] },
  { owner: 'omar', title: 'NDA: Globex (draft)', category: 'Legal', description: 'Draft NDA for a different client. Must never reach Acme.', filename: 'nda-globex-draft.pdf',
    body: ['Mutual Non-Disclosure Agreement (DRAFT)', 'Between TrustVault Demo Ltd and Globex Inc', 'Not for distribution.'], grants: [] },
  { owner: 'omar', title: 'Q3 audit working papers', category: 'Audit', description: 'Evidence prepared for the external auditor.', filename: 'q3-audit-papers.csv',
    raw: 'control,owner,status\nAccess reviews,IT Security,Passed\nBackups,Engineering,Passed\nVendor contracts,Legal,Open\n',
    grants: [{ to: 'olivia', permission: 'read' }] },
];

export async function seedIfEmpty({ log = console.log } = {}) {
  const [{ n }] = await query('SELECT count(*)::int AS n FROM users');
  if (n > 0) return false;

  const ids = {};
  await tx(async ({ query: q }) => {
    for (const u of DEMO_USERS) {
      ids[u.key] = randomUUID();
      await q(
        `INSERT INTO users (id, email, name, role, department, password_hash, is_demo, signup_source) VALUES ($1,$2,$3,$4,$5,$6,true,'seed')`,
        [ids[u.key], u.email, u.name, u.role, u.department, await hashPassword(u.password)],
      );
      await appendAudit(q, { action: 'user.create', targetUserId: ids[u.key], ip: 'seed', details: { email: u.email, role: u.role, seeded: true } });
    }
    for (const d of DEMO_DOCS) {
      const id = randomUUID();
      const owner = DEMO_USERS.find((u) => u.key === d.owner);
      const bytes = d.raw ? Buffer.from(d.raw, 'utf8') : makePdf(d.body);
      const mime = d.filename.endsWith('.pdf') ? 'application/pdf' : 'text/csv; charset=utf-8';
      const enc = encryptFile(bytes, `${id}:1`);
      await q(`INSERT INTO documents (id, owner_id, title, description, category) VALUES ($1,$2,$3,$4,$5)`, [id, ids[d.owner], d.title, d.description, d.category]);
      await q(
        `INSERT INTO document_versions (id, document_id, version, filename, mime_type, size_bytes, sha256, iv, auth_tag, ciphertext, uploaded_by)
         VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [randomUUID(), id, d.filename, mime, bytes.length, sha256Hex(bytes), enc.iv, enc.authTag, enc.ciphertext, ids[d.owner]],
      );
      await appendAudit(q, { actor: { id: ids[d.owner], email: owner.email }, action: 'document.upload', documentId: id, ip: 'seed', details: { title: d.title, filename: d.filename, seeded: true } });
      for (const g of d.grants) {
        const expires = g.days ? new Date(Date.now() + g.days * 24 * 3600 * 1000) : null;
        await q(`INSERT INTO grants (id, document_id, grantee_id, permission, granted_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, [
          randomUUID(), id, ids[g.to], g.permission, ids[d.owner], expires,
        ]);
        const grantee = DEMO_USERS.find((u) => u.key === g.to);
        await appendAudit(q, {
          actor: { id: ids[d.owner], email: owner.email }, action: 'permission.grant', documentId: id, targetUserId: ids[g.to], ip: 'seed',
          details: { grantee: grantee.email, permission: g.permission, expiresAt: expires, seeded: true },
        });
      }
    }
  });
  log(`Seeded ${DEMO_USERS.length} demo users and ${DEMO_DOCS.length} documents.`);
  return true;
}
