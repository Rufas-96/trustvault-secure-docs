# THREATS.md

How I believe TrustVault could be broken, what I did about each, the test that proves it, and
what I knowingly accepted. IDs in the **Test** column are `describe(...)` names in `test/`;
run `npm test` to see them. Every authorisation test in this file was also checked by
**removing the check it covers and confirming the test fails** (see PROMPTS.md entries 1, 5).

Status: **Closed** = mitigated and tested · **Partial** = mitigated with a known gap ·
**Accepted** = deliberately left, with the reason.

The single place a document access decision is made is `src/authz.js`
(`effectiveAccess` → `authorizeDoc` → `requireDocAccess`). Most of section 1 is about making
sure nothing can go around it.

---

## 1. Reaching a document you were not given

| ID | Attack | What stops it | Test | Status |
|---|---|---|---|---|
| T-01 | **IDOR**: change the document id in the URL or API call | Every `/documents/:id…` route runs `requireDocAccess(action)` first; the handler only ever sees `req.doc` after authorisation. Ids are random UUIDv4, but that is not relied on. | T-01/T-02 | Closed |
| T-02 | Use a **different route** to the same document: metadata, versions, `download?version=1`, rename, new version, delete, restore, grants, activity | All 12 routes are tested for 4 user/document pairs, and must also leave the document unchanged. | T-01/T-02 | Closed |
| T-03 | **Search/list leakage**: find titles of others' documents via `q`, `owner`, `category`, dates, `%` / `_` wildcards | The readable-by-me filter (`READABLE_BY_USER_SQL`) is always ANDed into the query; user filters only narrow it. `%` and `_` are escaped. | T-03 | Closed |
| T-06 | A **read** grantee edits, uploads a version, deletes, shares, or lists grants | Action → minimum level table in `authz.js`; anything not in the table is denied. | T-06 | Closed |
| T-07 | An **edit** grantee deletes, re-shares (grants themselves or a friend), or reads who else has access / the activity log | Those actions need `owner`, which is never granted, only derived from `documents.owner_id`. | T-07 | Closed |
| T-08 | A **viewer** holds an `edit` grant (old data, a bug, or direct DB write) and edits | `effectiveAccess` caps viewers at `read` at decision time, not only when the grant is created. | T-08 | Closed |
| T-09 | The **administrator** reads documents | Admins get no access level at all, in the decision function itself. They cannot be added as grantees, and a grant planted directly in the database still gives them nothing. | T-09, T-09b | Closed |
| T-10 | Grantees read a document after the owner **deleted** it (or the owner downloads from the trash) | Deleted documents are reachable only by the owner, only for `view`/`restore`, checked in two independent places. | T-10 | Closed |
| T-11 | Revoke (or tamper with) a grant on someone else's document by sending its grant id through **your own** document's URL | `DELETE …/grants/:grantId` includes `document_id = :id` in the `WHERE`. | T-11 | Closed |
| T-12 | **Role escalation**: viewer uploads, non-admin calls admin API, viewer browses the people directory, owner gives a viewer edit | `requireRole` on routes, plus grant rules (viewers read only, no admins, not yourself). | T-12, T-34 | Closed |
| T-23 | Malformed ids (SQL fragments, traversal, all-zero UUID) cause a 500 or reveal existence | `isUuid` check → `404`, the same as "no access". | T-23 | Closed |
| T-24 | **Existence probing**: 403 vs 404 tells an attacker a document exists | Refusals are always `404 Document not found`. A small timing difference between "no such row" and "row but no grant" remains (one extra indexed query). | (review) | Partial |
| T-26 | **Stored XSS** via a document title, filename, description or user name, to steal a session | All UI text is set with `textContent` (no `innerHTML` anywhere); CSP `script-src 'self'` with no inline scripts; the session cookie is `HttpOnly` anyway. | (review + CSP header check in live test) | Closed |
| T-27 | **SQL injection** in search, sort, filters | Parameterised queries everywhere; `ORDER BY` comes from a fixed map, never from input. JSON type confusion (`{"$ne":""}`, arrays) is rejected. | T-03, T-33 | Closed |

## 2. Keeping access after it was taken away

| ID | Attack | What stops it | Test | Status |
|---|---|---|---|---|
| T-04 | Keep using access **after revocation**: a cached page, a saved download link, a still-open session | There are no signed URLs, JWTs or cached decisions. Every request re-reads grants from the database, so a revoke applies to the next request of the same session. Downgrading edit→read also applies at once. | T-04 | Closed |
| T-04b | A download that **already passed** the check while the owner revokes | That single in-flight response completes; it was authorised at the moment it started, and its audit row records it. "Immediately" in this design means "on the next request". | (design) | Accepted |
| T-05 | Use a grant past its **expiry** | `expires_at > now()` is part of the grant lookup and of the list/search filter. Already-expired expiry dates are refused when sharing. | T-05 | Closed |
| T-14 | A **leaver** keeps working: open session, cookie copied to another machine | Disabling deletes every session row, and `loadSession` re-checks `is_active` on every request even if a session somehow survives. The person cannot sign in again. | T-14 | Closed |
| T-20 | The previous owner keeps access after an **ownership transfer** | Ownership is computed from `owner_id` at request time. | T-20 | Closed |
| T-22 | Replay a **cookie after logout** | Logout deletes the server-side session row; the token is dead, not just removed from the browser. | T-22 | Closed |
| T-28 | Copies already **downloaded** before revocation | Cannot be recalled by any system. The audit trail proves exactly who downloaded which version and when. No watermarking (see WRITEUP). | (inherent) | Accepted |

## 3. Proving who reached it (audit trail)

| ID | Attack | What stops it | Test | Status |
|---|---|---|---|---|
| T-15 | An access or change **is not recorded** | Successful changes write their audit row in the **same transaction** as the change. Downloads are audited before the bytes are sent (if the audit write fails, nothing is sent). Upload, download, edit, version, delete, restore, grant, change, revoke, transfer, sign-in and settings changes are all asserted. | T-15 | Closed |
| T-25 | **Refused attempts** leave no trace | Every refusal in `authorizeDoc`/`requireRole` and every failed sign-in, code or second factor is audited with actor, target and reason. | T-25, T-15 | Closed |
| T-16 | Someone with SQL access **edits or deletes** audit rows | Database triggers reject UPDATE, DELETE and TRUNCATE on `audit_log` for every role, including the table owner. | T-16 | Closed |
| T-17 | A database owner **disables the triggers** and edits, deletes, or inserts a forged row | Each row stores `HMAC(key, prev_hash, row)`. The key lives in the host environment, not the database. Editing breaks that row's hash, deleting breaks the next row's `prev_hash`, and a forged row cannot carry a valid HMAC. `/admin/audit/verify` and the admin overview report the exact entry. | T-16, T-17 | Closed |
| T-17b | An attacker with **both** the database **and** the HMAC key (full host compromise) rewrites the whole chain consistently | Not prevented. The fix is to anchor the chain head outside the system (e.g. periodically email or publish the latest hash) so a rewrite contradicts an earlier anchor. Not built. | (none) | Accepted |
| T-18 | Owners cannot see who touched their document, or see other people's | Owners see their own document's activity including refusals; non-owners get `404`. | T-18, T-07 | Closed |
| T-19 | The **IP address** in the evidence is wrong or spoofable | Found on the live site: every row first showed Render's load balancer, then a Cloudflare edge. Now only private ranges and Cloudflare's published ranges are trusted in `X-Forwarded-For`, so the first public address is the client, and a client-written `X-Forwarded-For` entry is never reached. Verified against the live audit trail. | (manual + script, PROMPTS #4) | Partial |
| T-19b | Someone who routes traffic through **their own Cloudflare Worker** arrives from a trusted Cloudflare range and could prepend a fake address | Residual risk of trusting Cloudflare's ranges. Recorded IP is evidence, not authentication; nothing is authorised by IP. | (none) | Accepted |
| T-29 | **Flood the audit log** with refused requests to bury evidence or fill the database | 300 requests/min per IP, and the admin overview groups refusals by actor ("probing" alert). | (review) | Partial |

## 4. Getting in as someone else (authentication)

| ID | Attack | What stops it | Test | Status |
|---|---|---|---|---|
| A-10 | **Password guessing** / credential stuffing | Policy: 12+ chars, common and personal passwords refused (NIST 800-63B style). scrypt hashing. 5 failures per (IP, email) and 30 per IP per 15 min. Identical message and timing (dummy hash) for unknown email, wrong password, disabled account. | T-33, A-04 | Partial |
| A-11 | Distributed guessing from many IPs (IPv6 rotation) | Per-IP limits do not stop this. I deliberately did **not** add hard account lockout: on a shared demo it would let one person lock everyone out of the published accounts. Two-factor is the real defence. | (none) | Accepted |
| A-12 | **Stolen session cookie** | `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix; only a hash is stored server-side; 30-min idle / 8-h absolute expiry; users see every session and can end any; password change and 2FA enrolment end other sessions. Not bound to IP (mobile users change IP constantly). | T-32, A-06 | Partial |
| A-13 | **CSRF**, including login CSRF (sign the victim into the attacker's account) | CSRF token header on every state change; SameSite=Strict; Origin check on every state change including sign-in and sign-up. | T-32, A-07 | Closed |
| A-14 | **Bypass two-factor** after the password step | No session exists until every factor is proven; the pending ticket is short-lived, single-purpose, 5 attempts. TOTP codes cannot be replayed (last used time-step stored). Recovery codes are single use. | A-01, A-02 | Closed |
| A-15 | Two-factor that is **the same factor twice** (SMS code then SMS code) | `secondFactorFor()`: SMS first → password second. | O-08 | Closed |
| A-16 | **Admin account without 2FA** | Real admin accounts cannot use any admin endpoint until an authenticator is on, and cannot turn it off. | A-03 | Closed |
| A-16b | The **published demo admin** has no 2FA | Evaluators share it; enforcing 2FA would let the first person to enrol lock out everyone else. The demo admin cannot read documents anyway (T-09). | (by design) | Accepted |
| A-17 | **Admin-set initial password** is known to the admin | Must be changed at first sign-in; every other endpoint is gated until it is. | A-03 | Closed |
| A-18 | **Password reset** used to take over or to skip 2FA | Code by email, bound to a ticket, 10 min, single use; reset ends every session and does not sign in, so the next sign-in still needs the second factor. | O-07 | Closed |
| A-19 | **Account enumeration** via sign-up, email-code sign-in, reset, or login | Identical responses for registered and unregistered addresses, **including the rate-limit behaviour** (found by a failing test, PROMPTS #5), and nothing is ever sent to unknown addresses. Login uses a dummy hash for unknown emails. | O-02, T-33 | Partial |
| A-19b | Timing on code requests: a real send waits for the email API (~0.3 s), an unknown address returns faster | Not equalised. The fix is a background send queue. | (none) | Accepted |
| A-20 | **Account pre-hijacking**: attacker registers the victim's email first, with the attacker's password | Unverified accounts cannot sign in; a later sign-up for the same address replaces the password, and whoever proves the inbox owns the account. | O-04, O-03 | Closed |
| A-21 | **OTP brute force** | 6 digits from `crypto.randomInt`, 10-minute expiry, 5 guesses then burned, code bound to a 256-bit ticket held by the requesting browser, stored as HMAC. | O-05 | Closed |
| A-22 | Use the server as a **spam / SMS-bombing relay** | 60 s cooldown and 5/hour per destination, 20/hour per IP; codes only go to verified accounts (an AI-introduced bug that emailed unknown addresses was caught, PROMPTS #5). | O-02, O-06 | Closed |
| A-23 | **SIM swap** defeats SMS codes | SMS is weaker than an authenticator; the authenticator takes priority when both exist, and admins must use an authenticator. | (design) | Accepted |
| A-24 | Claim **someone else's phone number** or verify it with a code sent to another account | Verified numbers are unique; a phone code is only valid for the account it was issued to. | O-08 | Closed |
| A-25 | **Bulk self sign-up** (bots) | 10 sign-ups per IP per hour; accounts are useless until the email is verified, and are viewers (cannot upload). No CAPTCHA. | O-01 | Partial |
| A-26 | **Lock evaluators out** by changing the published demo accounts | Demo accounts cannot have password/phone/2FA changed, or be disabled or demoted. | A-05, T-34 | Closed |

## 5. Malicious files

| ID | Attack | What stops it | Test | Status |
|---|---|---|---|---|
| T-30 | Upload **HTML/SVG/JS** (renamed `.pdf`/`.png`) to get script running on our origin | Extension allowlist **and** magic-byte check (contents must match the extension); served Content-Type comes from our table, never from the upload. | T-30 | Closed |
| T-31 | A stored file **executes in the browser** when downloaded | `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `no-store`. | T-31 | Closed |
| T-32f | **Path traversal** in the filename, or header injection via the filename | No filesystem storage at all (files live encrypted in the database); filenames are sanitised; `Content-Disposition` uses an ASCII fallback plus RFC 5987 encoding. | T-30 | Closed |
| T-33f | **Huge uploads** to exhaust memory | 10 MB limit, one file, few small fields; the role/authorisation check runs **before** the body is read. | T-30, T-12 | Partial |
| T-34f | **Swap ciphertext** between documents in the database so a grantee of A receives B | AES-GCM with the document id and version as additional authenticated data: a swapped blob fails to decrypt (500) instead of serving the wrong file. Also SHA-256 integrity check. | T-31 | Closed |
| T-35f | **Malware** inside a valid PDF/DOCX, PDF JavaScript, CSV formula injection when opened in Excel | Not scanned. Files are only ever downloaded, never rendered by us. | (none) | Accepted |

## 6. Infrastructure and secrets

| ID | Attack | What stops it | Test | Status |
|---|---|---|---|---|
| T-40 | **Database stolen** (backup, provider staff, leaked credentials) | File contents and TOTP secrets are AES-256-GCM encrypted with a key stored on the host, not in the database. Passwords scrypt-hashed, session tokens and codes hashed. **Metadata (titles, names, audit rows) is not encrypted.** | T-31, A-02 | Partial |
| T-41 | **Network attacker** between app and database | TLS with certificate verification (an AI-generated `rejectUnauthorized: false` was caught, PROMPTS #3). | (review) | Closed |
| T-42 | Plain **HTTP / downgrade** | Render redirects to HTTPS (verified live: 301); HSTS header. | live check | Closed |
| T-43 | **Clickjacking** | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | live check | Closed |
| T-44 | **Secrets in the repository** | None: keys are generated by Render (`generateValue`), `.env*` and `.neon` are git-ignored; production refuses to start without keys. | (review) | Closed |
| T-45 | **Dependency** compromise | Five runtime dependencies, lockfile committed, `npm audit` clean at time of writing. | (review) | Partial |
| T-46 | Rate limits **reset on restart** or differ between instances | Sign-in and per-IP limits are in memory (one instance on Render). Code limits per address are in the database and survive restarts. | (design) | Accepted |

## 7. Trusted insiders

| ID | Attack | What stops it | Test | Status |
|---|---|---|---|---|
| T-50 | An **administrator** wants to read a document. They cannot open it directly, but can (a) transfer it to an owner account they control, or (b) reset a user's password and sign in as them | Not prevented: administrators can manage accounts, and that power reaches content indirectly. Both paths are loud: `document.transfer`, `user.password_reset` and the subsequent `auth.login` are in the tamper-evident trail, and a reset forces the victim to choose a new password (they notice). A real deployment should require a second admin to approve transfers and resets. | T-20, A-06 | Accepted |
| T-51 | An **owner** shares with the wrong person | The share dialog shows name, email, role and department; viewers can only get read; expiry can be set; the owner sees every access in Activity and can revoke instantly. | T-04, T-05 | Partial |
| T-52 | Owners can see the **people directory** (names, emails of all non-admin users) | Needed to share with named people. Viewers and self sign-ups cannot see it. | T-12 | Accepted |

---

## Found that I had not expected

These came from testing my own system, not from a checklist:

1. **The audit trail recorded the wrong IP on the real host.** Locally there is no proxy, so
   every test passed; on Render every refusal came "from" the load balancer, then from
   Cloudflare. (T-19)
2. **Rate limiting can itself enumerate accounts.** Identical response bodies are not enough
   when only real sends trigger the cooldown. (A-19)
3. **A JavaScript default parameter turned "do not send" into "send"** (`undefined` → `true`),
   emailing codes to addresses with no account. (A-22)
4. **Copying ciphertext between rows** would have served the wrong document to a legitimate
   grantee, without AAD binding. (T-34f)
5. **SMS two-factor locked out a person who had just typed the correct password** when the
   text hit its own cooldown. Not a confidentiality issue, but an availability one. (PROMPTS #6)
