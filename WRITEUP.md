# TrustVault: write-up

## What I built

A document-sharing service where access is decided by the server on every request, taken
away the moment an owner says so, and recorded in an audit trail that shows tampering.

- **Documents:** upload (owners), versions, edit details, soft delete and restore, search by
  name, owner, category and date. Files are validated by content, encrypted at rest, and only
  ever served as downloads.
- **Permissions:** per-document grants to named people, read or edit, with optional
  expiry; grant, change and revoke; ownership transfer for leavers.
- **Audit:** every access and change including refusals, append-only in the database and
  HMAC-chained, with chain verification and alerts on the admin overview.
- **Authentication:** verified self sign-up; sign-in by password or email code; second
  factor by authenticator app with recovery codes; forgotten-password flow; mandatory
  authenticator for administrators; session management and personal security activity.
- **Tests:** access control on every route, revocation, audit tampering, uploads,
  sessions/CSRF, sign-in, two-factor and one-time codes. Each authorisation check was
  verified by deleting it and watching a test fail.

Live: https://trustvault-secure-docs.onrender.com · details in [README.md](README.md).

## The permission model, in my own words

There are three roles, and one question answered for every request: *what is this person's
level on this document right now?*

- The **owner** is whoever `documents.owner_id` points at. Owner is never granted, so it
  cannot be handed out by mistake. The owner can do everything with their document,
  including deciding who else may see it.
- Everyone else gets a level only from a **live grant**: a row in `grants` for that exact
  document and that exact person, not revoked, not expired. `read` lets you open and
  download; `edit` adds changing details and uploading versions. Nothing lets a grantee
  delete, re-share, or see who else has access. Those stay with the owner.
- **Viewers** (including everyone who signs up themselves) can only ever have `read`, and
  that cap is applied when access is decided, not just when the grant is created.
- **Administrators have no document level at all.** They manage people and watch the audit
  trail; they cannot open content. Keeping that power separate means the person who can see
  every log line cannot quietly read the files.

The decision is one function, `effectiveAccess` in `src/authz.js`, and every document route
calls it through `requireDocAccess(action)` before its handler runs. If you remove that call
from the download route, a request from anyone with a session gets the file, and 12 of the 83 tests
fail. A refusal is a `404`, so guessing ids tells you nothing, and every refusal is audited.

**What "taking access away immediately" means here:** nothing that outlives a decision is
ever issued. There are no signed links, no JWTs, no cached permissions; the session is just a
random key that is looked up in the database each time, together with the grants. So a
revoke, an expiry, a deleted document or a disabled account applies to the very next request.
The cost is one or two extra indexed queries per request, and no offline or CDN-cached file
access. I think that is the right trade for confidential documents. A file someone already
downloaded cannot be recalled, but the trail shows exactly who downloaded which version.

**Why per-document grants and not folders or groups:** the brief's first failure story is
"given access to a folder to see one file, and they can now see forty". Inheritance is
exactly how that happens. Explicit per-document grants are more clicks for owners, but every
person's access to every document is one row you can point at, and the "Sharing" tab shows
the complete list plus its history.

## What I deliberately did not build, and why

| Not built | Why |
|---|---|
| **Public / external share links** | A link is a bearer token: whoever holds it gets in, and it survives the person leaving. External partners get a normal account (see Vera in the demo) with an expiring grant instead. |
| **Folders and group permissions** | See above; inheritance is the over-sharing failure mode. |
| **In-browser preview** of PDFs and images | Rendering uploaded content on our origin is an XSS surface. Download-only with a sandbox CSP is safer. |
| **AI suggestions for who should see a document** | It would have to read document contents or sharing history. Its value is low next to the risk of an AI widening access, and I preferred to spend the time on authentication and testing. If built, it would only *suggest*; a person confirms, and both go in the audit. |
| **Hard delete, retention policies** | Deletion is soft (restorable); permanent deletion and legal retention rules need decisions a real company would make. |
| **Mobile number / SMS codes** | I built SMS sign-in and SMS two-factor, with tests, then removed them. Real texts to Indian numbers need a paid provider and DLT registration, so the feature could not work live; an authenticator app is also stronger than SMS (SIM swap), and unused endpoints are attack surface. |
| **Malware scanning, watermarking** | Need external services; listed as accepted risks in THREATS.md. |

## How I used AI, and where it was wrong

I used **Claude Code** throughout, with a standing brief I wrote first
([docs/AI-CONTEXT.md](docs/AI-CONTEXT.md): server decides every time, deny by default, no
bearer tokens, append-only audit, tests must prove denial). [PROMPTS.md](PROMPTS.md) has dated
entries; the important ones:

1. **A green test suite that did not test revocation or expiry.** I removed checks one at a
   time; three removals still passed. I added the revocation tests until every removal failed.
2. **An audit-tampering test that never tampered.** It asserted structure instead of
   deleting a row. Rewrote it to really delete, forge and restore, and assert the exact break.
3. **`rejectUnauthorized: false` on the database connection**, which would allow a network
   attacker to impersonate the database. Turned verification on.
4. **The audit trail recorded the load balancer as "who"** on the real host. The AI assumed
   one proxy; there were two (Render and Cloudflare). Found by testing the live site.
5. **Account enumeration through the rate limiter, and codes emailed to strangers**, caused
   by a JavaScript default parameter. Found because my own mutation check "passed" when it
   should not have.
6. **SMS two-factor locked out a user who typed the right password** (SMS has since been removed). Found only by driving
   the real UI.

The pattern I learned: the AI writes code that passes the tests it also writes. The bugs
showed up when I broke the code on purpose, ran it on the real host, or clicked through it.

## What is unfinished

- **Code emails can land in Spam**, because they are sent from a free Gmail address via
  Brevo; a custom domain with SPF/DKIM would fix that.
- **Audit chain anchoring:** someone with both the database and the server's key could
  rewrite the whole chain. Periodically publishing the chain head elsewhere would close that.
- **Timing differences** on code requests (real sends are slower) could hint which emails
  exist; a background send queue would equalise it.
- **Admin powers reach content indirectly** (transfer to an account they control, or reset a
  user's password). Both are loudly audited; a two-person approval is the real fix.
- Rate limits for sign-in are in memory (fine on one instance, not on several).

Full list with reasoning: [THREATS.md](THREATS.md), sections marked *Partial* and *Accepted*.
