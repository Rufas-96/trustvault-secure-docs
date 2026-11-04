# TrustVault

Secure document sharing where **the wrong person cannot reach a file, and you can prove who did**.
Every request is authorised by the server against the database, revocation takes effect on the
very next request, and every access, including refused ones, lands on an append-only,
HMAC-chained audit trail.

**Live:** https://trustvault-secure-docs.onrender.com
(free hosting: the first request after ~15 idle minutes can take 30–50 s while the server wakes up)

| Document | What it covers |
|---|---|
| [THREATS.md](THREATS.md) | How this could be attacked, what stops each attack, the test that proves it, and what I accepted |
| [API.md](API.md) | Every endpoint and exactly who may call it |
| [WRITEUP.md](WRITEUP.md) | What I built, what I left out, the permission model in my own words, AI use, what is unfinished |
| [PROMPTS.md](PROMPTS.md) | Dated log of where the AI was wrong and what I did instead |
| [docs/AI-CONTEXT.md](docs/AI-CONTEXT.md) | The standing brief I gave the AI in every session |

---

## Demo accounts

The live site is seeded with these accounts. They are shared by everyone evaluating, so their
password, phone and two-factor settings are locked, and they cannot be disabled. To try
sign-up, two-factor or password reset, **create your own account** on the sign-in page.

| Role | Email | Password | What to try |
|---|---|---|---|
| Administrator | `admin@trustvault.demo` | `Admin#Vault2026` | Security overview, audit trail + chain verification, people, ownership transfer. Cannot open any document. |
| Owner (HR) | `olivia.owner@trustvault.demo` | `Owner#Vault2026` | Owns 3 documents: share, revoke, upload versions, see each document's activity |
| Owner (Legal) | `omar.owner@trustvault.demo` | `Owner2#Vault2026` | Owns 3 documents; has *edit* on Olivia's handbook |
| Viewer (employee) | `vik.viewer@trustvault.demo` | `Viewer#Vault2026` | Sees exactly 2 documents shared with him |
| Viewer (external partner) | `vera.partner@trustvault.demo` | `Partner#Vault2026` | Sees exactly 1 document, with a 30-day expiry |

Things worth attempting: as Vik or Vera, request another document's id from the URL bar or
the API, try `/download?version=1`, try sharing to yourself, try the admin API. Then sign in
as the admin and find your attempts under **Audit trail → Refused**.

---

## What works

**Documents and permissions**
- Upload (owners), versioning, rename/re-describe/re-categorise, soft delete and restore.
- Per-document grants to named people: **read** or **edit**, optional expiry. Owners grant,
  change and revoke; revocation is immediate.
- Search by name/file/description, owner, category and date range, never returning anything
  the caller cannot read.
- Upload validation: 10 MB limit, extension allowlist, **file contents must match the
  extension** (magic bytes), filenames sanitised. Files are AES-256-GCM encrypted in the
  database and only ever served as downloads with `nosniff` and a sandbox CSP.

**Audit**
- Every upload, download, edit, version, delete/restore, grant/change/revoke, transfer,
  sign-in and settings change, **including refused attempts**, with actor, time and client IP.
- Append-only (database triggers reject UPDATE/DELETE/TRUNCATE) and HMAC-chained with a key
  that is not in the database; the admin overview verifies the chain and raises a critical
  alert if any row was edited, removed or inserted.
- Admin overview flags probing (repeated refusals), bulk downloads, failed sign-ins,
  grants held by disabled accounts, and documents whose owner was disabled.

**Authentication**
- Passwords: 12+ characters, common and personal passwords refused, scrypt hashing,
  throttled sign-in with identical errors for unknown emails.
- **Create an account** with email verification by one-time code (new accounts are viewers;
  an admin can promote them to owner).
- Sign in with **password**, **email code**, or **SMS code**; second factor by
  **authenticator app (TOTP, with recovery codes)** or **SMS code**. Never the same factor
  twice. Administrator accounts (other than the shared demo) must use an authenticator.
- Forgotten password by email code (ends every session, keeps two-factor).
- Account security page: protection score, recent sign-in activity including failed
  attempts, active sessions with "sign out" per device or everywhere.
- Server-side sessions (HttpOnly, Secure, SameSite=Strict, `__Host-` cookie), CSRF token on
  every state change, Origin check, 30-minute idle / 8-hour absolute expiry.

### Known limitations on the live deployment
- **SMS is switched off.** It is fully built and tested, but needs a Twilio account
  (`TWILIO_*` variables). The site says so instead of pretending; see [WRITEUP.md](WRITEUP.md).
- **Code emails may land in Spam/Promotions.** They are sent through Brevo from a free
  @gmail.com address, which cannot pass Gmail's DMARC alignment without a custom domain.
- Free Render instances sleep when idle (slow first request).

---

## Run it locally

Requires **Node.js 22+**. No database to install: without `DATABASE_URL` the app runs on
[PGlite](https://github.com/electric-sql/pglite) (real PostgreSQL compiled to WebAssembly),
stored in `.data/`.

```bash
git clone https://github.com/Rufas-96/trustvault-secure-docs.git
cd trustvault-secure-docs
npm install
npm start          # http://localhost:3000, demo data is seeded on first start
```

In development, email and SMS codes are **printed to the server console** instead of being sent.

Run the tests (each test file starts from a fresh in-memory database):

```bash
npm test
```

Start again from empty demo data: stop the server and delete the `.data/` folder.

### Configuration

| Variable | Needed | Purpose |
|---|---|---|
| `DATABASE_URL` | production | PostgreSQL 15+ connection string. Use `sslmode=verify-full`; certificates are always verified. |
| `FILE_ENCRYPTION_KEY` | production | 32 random bytes (base64), or any 32+ char secret. **Never change it**: stored files become unreadable. |
| `AUDIT_HMAC_KEY` | production | Same format. **Never change it**: the audit chain stops verifying. |
| `NODE_ENV` | production | `production` enables secure cookies, HSTS, proxy trust, and refuses to start without the keys. |
| `BREVO_API_KEY`, `MAIL_FROM`, `MAIL_FROM_NAME` | optional | Email codes (sign-up, email sign-in, password reset). `MAIL_FROM` must be a verified Brevo sender. |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` | optional | SMS codes. |
| `SEED_ON_BOOT` | optional | `false` to skip demo data in an empty database. |
| `TRUST_PROXY` | optional | Override proxy trust (default in production: private ranges + Cloudflare). |

Generate a key: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`

---

## Deploy (Render + Neon, both free)

1. Create a PostgreSQL database on [Neon](https://neon.tech) and copy its pooled connection
   string. Change `sslmode=require` to `sslmode=verify-full`.
2. On [Render](https://render.com): **New → Blueprint**, choose this repository. `render.yaml`
   creates the web service (Singapore, Node 24) and **generates both keys for you**.
3. Paste the connection string when Render asks for `DATABASE_URL`, and deploy.
4. Optional: add the Brevo / Twilio variables under **Environment**.

The schema (`db/schema.sql`) is idempotent and applied on every start; demo data is seeded
only when the database has no users, by the server itself, so it is encrypted with the
production keys.

---

## How it is built

Node.js 24, Express 5, PostgreSQL, vanilla JavaScript front end with no build step and no
inline scripts (strict CSP). About 20 source files:

```
src/
  authz.js        THE authorisation decision for documents (read this first)
  auth.js         sessions, sign-in flows, two-factor, CSRF/Origin checks, account routes
  otp.js          one-time codes: generation, hashing, rate limits, verification
  audit.js        append-only HMAC-chained audit trail + chain verification
  files.js        upload validation and safe download headers
  crypto.js       scrypt, AES-256-GCM, tokens      mfa.js  TOTP (RFC 6238)
  routes/         documents.js, admin.js, users.js
db/schema.sql     tables, indexes, append-only triggers
test/             access control, revocation, audit tampering, uploads, auth, OTP
public/           the web app
```

Why this stack: one language end to end, a small dependency list I can explain line by line
(`express`, `pg`, `multer`, `qrcode`, `@electric-sql/pglite`), and real PostgreSQL in
development and tests, so the triggers and SQL that protect the audit trail are the same
ones that run in production.
