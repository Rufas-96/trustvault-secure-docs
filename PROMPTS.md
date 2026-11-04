# PROMPTS.md: how I used AI on TrustVault

Tool: **Claude Code** (Claude Opus 5.5), used in the terminal for the whole build.
Standing context I reused in every session: [`docs/AI-CONTEXT.md`](docs/AI-CONTEXT.md).

Entries are written as the work happens, newest last. Each one says what I asked for,
what the tool produced, what was wrong with it, and what I did instead, with the commit.

---

## 1. 2026-11-04: Access-control tests that were green but not testing revocation (authorisation)

**Asked:** "Write automated tests proving one user cannot reach another user's documents.
Cover every route that takes a document id, for a user with no grant, read, and edit.
Follow docs/AI-CONTEXT.md rule 7: if an authorisation check is removed, a test must fail."

**Produced:** `test/access-control.test.js`: 20 tests, all passing. It covered every
document route for users with no grant, read vs. edit, search leakage, admin access, and
cross-document grant revocation.

**What was wrong:** The brief says the judges will delete one authorisation check and rerun
the tests, so I did that myself. I removed checks from `src/authz.js` one at a time with
`sed`, ran `npm test`, then restored with `git checkout`:

| Check removed | Tests failing |
|---|---|
| `requireDocAccess` on download | 8 ✔ |
| viewer capped at read | 3 ✔ |
| search's `READABLE_BY_USER_SQL` filter | 3 ✔ |
| `revoked_at IS NULL` in the grant lookup | **0** ✘ |
| `expires_at > now()` in the grant lookup | **0** ✘ |
| "admins get no document access" line | **0** ✘ |

Revocation and expiry are two of the three non-negotiables, and nothing tested them. The
admin rule was never exercised: in the seed data no admin holds a grant, so the line could
go without anything changing.

**What I did instead:** I wrote `test/revocation.test.js`. It covers revoke, then the same
session is refused on the next request; downgrading edit to read; an expired grant is
refused; disabling a user kills a live session; ownership transfer; and replaying a cookie
after logout. For the admin rule I plant a grant for the admin directly in the database and
assert it still gives nothing. I reran the mutations: every one now fails at least one test,
and so do two new ones on the session code (`is_active` re-check, logout deleting the
session row). Commit: [0370ee4](../../commit/0370ee4).

**Lesson I kept:** a passing suite proves nothing until you have seen it fail. Mutation
checks are now part of my routine for every authorisation change.

---

## 2. 2026-11-04: An audit tamper test that never deleted anything (audit trail)

**Asked:** "Add tests proving the audit trail cannot be quietly altered: UPDATE/DELETE/TRUNCATE
are blocked, and the HMAC chain detects an edited row and a deleted row."

**Produced:** The blocked-statements test and the edited-row test were real. But the "T-17
deleting an audit row is detected" test only read six rows and asserted
`rows[2].prev_hash === rows[1].hash`. It deleted nothing and never called `verifyChain()`.
It also had a leftover `assert.ok(createHmac)` that tests nothing at all. The tool's own
comment admitted why: the previous test had left the chain broken, so it "checked the
mechanism on a copy of the rows" instead. That test would still pass if `verifyChain()`
ignored `prev_hash` completely, which is exactly the check that catches a deleted row.

**What was wrong underneath:** the edited-row test never repaired the row it tampered with,
so every later test started from a broken chain. Instead of fixing the cause, the tool wrote
a weaker test around it.

**What I did instead:** each tamper test now disables the trigger, tampers, asserts
`verifyChain()` reports the exact `brokenAt` entry and the right reason, then puts the
original row back, re-enables the trigger, and asserts the chain is intact again. The
deletion test really deletes a row and expects the break at the *next* row. I also added a
test the tool had not thought of: an attacker with SQL access appends a forged row whose hash
is a plain SHA-256, because the HMAC key is not in the database. `verifyChain()` must flag it.
Commit: [44b2eb0](../../commit/44b2eb0).

---

## 3. 2026-11-04: Database TLS with certificate checking switched off (data in transit)

**Asked:** "Write a DB adapter: node-postgres when DATABASE_URL is set, PGlite otherwise."

**Produced:** A clean adapter, with this line for production:
`ssl: ... : { rejectUnauthorized: false }`. That is the snippet most hosting tutorials paste.

**What was wrong:** `rejectUnauthorized: false` encrypts the connection but never checks
*who* is on the other end. Anyone who can sit in the network path between Render and the
database can present any certificate, and the app will happily send every document's
ciphertext, every audit row, and the session table to them. In a product whose whole point is
"the wrong person cannot reach the file", that is a hole below the application layer, and
every authorisation check above it would be irrelevant.

**What I did instead:** certificates are verified (`rejectUnauthorized: true`). Neon serves a
publicly trusted certificate, so nothing else is needed. Local development without TLS has to
say so explicitly with `sslmode=disable`. I found it while preparing the deployment config,
reading the adapter line by line before pointing it at a real database.
Commit: [2497d81](../../commit/2497d81).

---

## 4. 2026-11-04: Every audit entry recorded Render's load balancer as "who" (audit trail)

**Asked:** "Prepare the app for Render: trust the proxy so `req.ip` is the real client."

**Produced:** `app.set('trust proxy', 1)`, with the comment "Render puts one proxy in front of
us". That is the standard snippet, and it passed every local test, because locally there is
no proxy at all.

**What was wrong:** After deploying I ran a black-box script against the live site. 30 of 32
checks passed, but every refused attempt in the audit trail came "from" `10.31.76.3`, Render's
internal load balancer. The brief says "you can prove who reached it", and an IP column where
every row is identical proves nothing. The first fix (trust private ranges only) then recorded
`104.23.160.28`, a Cloudflare edge address, so there are *two* proxy layers: client →
Cloudflare → Render's private network → app. The AI's "one proxy" assumption was wrong twice.

**What I did instead:** `trust proxy` now skips only private ranges plus Cloudflare's
published ranges, so the first remaining address is the client. I proved it two ways: a
local test where a client prepends a fake `X-Forwarded-For` entry and is still identified
correctly, and a poll of the live audit trail until it recorded my real ISP address. A fixed
hop count is fragile, and `trust proxy: true` would let anyone spoof their IP into the evidence
log, so I rejected both. Commits: [63616f9](../../commit/63616f9),
[b7b96a4](../../commit/b7b96a4).

---

## 5. 2026-11-04: OTP sign-in leaked which emails have accounts, and emailed strangers (authentication)

**Asked:** "Add email one-time codes for sign-up, passwordless sign-in and password reset.
Unknown emails must get the same response as known ones (no account enumeration)."

**Produced:** `issueCode({ ..., send: deliverable(user) })` with `send = true` as a default
parameter, and an early `if (!send) return { ticket }` placed *before* the rate-limit check.
The response bodies for known and unknown emails were identical, as asked.

**What was wrong (two bugs, found by one failing test):**
1. *Enumeration through the rate limiter.* Only real sends counted toward the 60-second
   cooldown. Ask for a code twice: a registered email answers `429` the second time, an
   unregistered one answers `200` both times. Identical bodies, different behaviour.
2. *Emailing addresses with no account.* `deliverable(undefined)` returns `undefined`, not
   `false`, and a JavaScript default parameter replaces `undefined`, so `send = true` kicked
   in. The server really did email codes to arbitrary addresses (useless codes, but a spam
   relay). My first mutation test still "passed" with the leak re-introduced. That made no
   sense, so I printed the actual statuses and found bug 2 hiding bug 1.

**What I did instead:** limits and the stored row now apply identically whether or not we
deliver. `deliverable()` returns a real boolean, and `issueCode` *throws* unless `send` is
an explicit `true` or `false`; every call site states which. The test now replays
"request twice" for a known and an unknown address on both endpoints and asserts identical
`[status, keys, status]` sequences, *and* that the unknown address received nothing. Both
bugs, re-introduced one at a time, now fail it. Commit: [55945f5](../../commit/55945f5).

---

## 6. 2026-11-04: A correct password could not sign in with SMS two-factor

**Asked:** "Add SMS as a second factor, using the same rate-limited code engine."

**Produced:** At sign-in, after the password, `issueCode('second_sms')`. If that threw, the
whole login failed.

**What was wrong:** It only showed up driving the real UI in a browser, not in API tests.
Verifying a phone number sends a text. Turning on SMS two-factor and signing in within a
minute meant the second-factor text hit the 60-second cooldown, so the person got "Please
wait 55 seconds" *after typing the right password* and could not get in. In the same session
the AI also made `channels()` report email as enabled in development without keeping the
console fallback, so the dev server tried to call Brevo with no key (`401`).

**What I did instead:** when the second-factor text is rate-limited, the second step opens
anyway with `smsCooldown`, the screen says a code was sent moments ago, and the Resend
button counts down. The limits themselves are unchanged. I added a regression test (phone
verified → SMS 2FA on → immediate sign-in → still reaches the SMS step → resend → signed in).
"Is a provider configured?" and "is this channel offered?" are now separate functions.
Commit: [c4ebe16](../../commit/c4ebe16).
