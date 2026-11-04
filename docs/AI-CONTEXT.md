# AI context file (reused across the week)

I paste or reference this file at the start of every AI coding session on TrustVault.
It is the standing brief; individual prompts in PROMPTS.md build on it.

## What we are building
TrustVault: document sharing where the wrong person cannot reach a document and we can
prove who did. Node.js + Express 5, PostgreSQL (PGlite locally and in tests, hosted
Postgres in production), vanilla JS front end with no build step.

## Non-negotiable rules for any code you write
1. **The server decides, every time.** Every route that touches a document must go through
   `src/authz.js` (`requireDocAccess` / `canAccess`). No route may read `documents`,
   `document_versions` or `grants` for a user without that check. Hiding a button is
   not access control.
2. **Deny by default.** Unknown action, missing grant, expired grant, deleted document,
   inactive user: all deny. Denials return 404 (do not confirm the document exists) and are
   written to the audit trail.
3. **No bearer artefacts that outlive revocation.** No signed URLs, no JWTs, no cached
   permission decisions. Sessions are opaque random tokens looked up in the DB on every
   request, so revoking a grant or disabling a user takes effect on the next request.
4. **The audit log is append-only.** Write only through `src/audit.js`. Never UPDATE or
   DELETE `audit_log`; the database triggers will reject it anyway. Every entry is
   HMAC-chained to the previous one.
5. **Parameterised SQL only.** No string-built queries, including ORDER BY and LIKE.
6. **Uploaded bytes are never trusted.** Size limit, extension allowlist, magic-byte check,
   stored encrypted in the database, served only as `attachment` with `nosniff` and a
   sandbox CSP.
7. **Tests prove denial.** Every new route gets a test where a user without access is
   refused. If you remove the authorisation check, a test must fail.

## How I want answers
- Small, explainable functions. I must be able to walk through this code in an interview.
- Tell me what you are unsure about rather than guessing.
- When you change authorisation or audit code, say exactly which check moved.
