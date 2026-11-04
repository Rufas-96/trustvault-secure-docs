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
