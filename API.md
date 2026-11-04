# TrustVault API

Base path: `/api`. JSON in and out, except uploads (`multipart/form-data`) and downloads (file bytes).

## Rules that apply to every endpoint

| Rule | Where it is enforced |
|---|---|
| **Session**: an opaque random token in an `HttpOnly; Secure; SameSite=Strict` cookie (`__Host-tv_session` in production). Only its SHA-256 is stored. It is looked up in the database on every request, so a disabled user or a deleted session is refused on the next request. | `loadSession` in `src/auth.js` |
| **CSRF**: every `POST/PATCH/DELETE` from a signed-in user must send `X-CSRF-Token` (returned by sign-in, `/me` and `/session`). Missing or wrong → `403`. | `requireCsrf` |
| **Origin**: a state-changing request whose `Origin` header names another site → `403`, including sign-in and sign-up. | `requireSameOrigin` |
| **Account gate**: while an account must change its admin-set password, or is a real administrator without an authenticator, every document/user/admin endpoint returns `403` with `details.code` = `PASSWORD_CHANGE_REQUIRED` or `MFA_SETUP_REQUIRED`. Only `/auth/*` stays open, so they can fix it. | `requireAccountReady` |
| **Rate limits**: 300 API requests/min per IP; sign-in 5 failures per (IP, email) and 30 per IP per 15 min; codes: one per address per 60 s, 5 per address and 20 per IP per hour; 5 guesses per code or second-factor step. | `src/app.js`, `src/auth.js`, `src/otp.js` |
| **Errors**: `{ "error": "message", "details"?: {...} }`. Server errors never include stack traces. | error handler in `src/app.js` |
| **Document access** is decided only by `requireDocAccess(action)` in `src/authz.js`. A refused document request is **`404`**, never `403`, so probing ids does not reveal which documents exist, and the refusal is audited. | `src/authz.js` |

### Roles and document access levels

| | read grant | edit grant | owner | admin |
|---|:-:|:-:|:-:|:-:|
| view metadata, list versions, download | ✔ | ✔ | ✔ | ✘ |
| rename / re-describe / re-categorise, upload new version | | ✔ | ✔ | ✘ |
| delete, restore, share, revoke, see grants, see activity | | | ✔ | ✘ |
| upload new documents | role **owner** only | | | ✘ |
| admin endpoints | | | | ✔ |

Viewers are capped at **read** even if an edit grant exists. Expired or revoked grants give
nothing. A deleted document is reachable only by its owner, only to view it in the trash
or restore it.

---

## Public (no session)

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/config` | anyone | Categories, allowed file types, size limit, password minimum, and which code channels (`email`, `sms`) are enabled. |
| GET | `/session` | anyone | `{ user, csrfToken }` if signed in, else `{ user: null }`. |
| POST | `/auth/login` | anyone | `{ email, password }` → `{ user, csrfToken, lastSignIn }`, or `{ mfaRequired, mfaToken, method }` when a second factor is needed. Unverified email → `403 EMAIL_NOT_VERIFIED` with a new code ticket. Same `401` for unknown email, wrong password, disabled account. |
| POST | `/auth/mfa` | holder of an `mfaToken` | Second factor. `method: totp` → `{ code }` or `{ recoveryCode }`; `sms` → `{ smsTicket, code }`; `password` → `{ password }`. 5 wrong attempts burn the token. |
| POST | `/auth/mfa/resend-sms` | holder of an `mfaToken` | New SMS code for the pending sign-in. |
| POST | `/auth/signup` | anyone | `{ name, email, password, phone? }` → `{ ticket, sentTo }`. Creates a **viewer** with an unverified email. Identical response if the email is already registered (nothing is sent). |
| POST | `/auth/signup/verify` | holder of the ticket | `{ ticket, code }` → signed in. |
| POST | `/auth/signup/resend` | anyone | `{ email }` → new ticket. Sends only to unverified self sign-ups. |
| POST | `/auth/email-code/start` | anyone | `{ email }` → `{ ticket, sentTo }`. Sends only to verified, active, non-demo accounts; identical response and limits otherwise. `503` if email is not configured. |
| POST | `/auth/email-code/verify` | holder of the ticket | `{ ticket, code }` → signed in, or second-factor step. |
| POST | `/auth/sms-code/start` | anyone | `{ phone }` (Indian 10-digit or E.164). Sends only to a verified number. `503 SMS_DISABLED` without a provider. |
| POST | `/auth/sms-code/verify` | holder of the ticket | `{ ticket, code }` → second factor (password, or authenticator if enabled). |
| POST | `/auth/password-reset/start` | anyone | `{ email }` → `{ ticket, sentTo }`. Identical response for unknown emails. |
| POST | `/auth/password-reset/complete` | holder of the ticket | `{ ticket, code, newPassword }`. Ends every session; does not sign in; two-factor stays on. |

## Signed in: your own account

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/me` | any signed-in user | Your profile (never secrets) and CSRF token. |
| POST | `/auth/logout` | any signed-in user | Deletes the session row, not just the cookie. |
| POST | `/auth/password` | any signed-in user except demo accounts | `{ currentPassword, newPassword }`. Ends your other sessions. |
| GET | `/auth/sessions` | any signed-in user | Your sessions only (id, device, IP, times). |
| DELETE | `/auth/sessions/:sid` | any signed-in user | Ends one of **your** sessions; someone else's id → `404`. |
| POST | `/auth/sessions/revoke-others` | any signed-in user | Ends all your sessions except this one. |
| GET | `/auth/activity` | any signed-in user | Last 20 authentication events on your account, including failed attempts against it. |
| POST | `/auth/mfa/setup` | non-demo users | New TOTP secret + QR code (not active until enabled). |
| POST | `/auth/mfa/enable` | non-demo users | `{ code }` → 10 one-time recovery codes (shown once). Ends other sessions. |
| POST | `/auth/mfa/disable` | non-admin users | `{ password, code }`. Real administrators cannot disable it. |
| GET | `/auth/mfa/recovery-codes` | any signed-in user | Number of unused recovery codes. |
| POST | `/auth/phone/start` | non-demo users | `{ phone }` → SMS code. `409` if verified on another account. |
| POST | `/auth/phone/verify` | the account the code was issued to | `{ ticket, code }`. |
| POST | `/auth/phone/remove` | non-demo users | `{ password }`. Also turns off SMS two-factor. |
| POST | `/auth/sms-2fa` | non-demo users with a verified phone | `{ enabled, password }`. |

## Documents

`:id` must be a UUID; anything else is `404`.

| Method | Path | Who (decided in `src/authz.js`) | Notes |
|---|---|---|---|
| GET | `/documents` | signed in | Search: `q` (title, filename, description), `owner` (name/email), `category`, `from`, `to` (YYYY-MM-DD), `scope` (`all`/`mine`/`shared`), `sort` (`newest`/`oldest`/`title`). **Only documents you can read**; admins get none. Max 200. |
| POST | `/documents` | role **owner** (checked before the body is read) | multipart: `file`, `title`, `category`, `description?`. 10 MB; contents must match the extension. |
| GET | `/documents/trash` | role **owner** | Your own deleted documents. |
| GET | `/documents/:id` | read, edit or owner | Metadata + `myAccess`. |
| GET | `/documents/:id/versions` | read, edit or owner | Version list with SHA-256 of each. |
| GET | `/documents/:id/download` | read, edit or owner | `?version=n` optional. Audited **before** the file is sent. `Content-Disposition: attachment`, `nosniff`, `CSP: sandbox`, `no-store`. |
| PATCH | `/documents/:id` | edit or owner | `{ title?, description?, category? }`. Audited with before/after. |
| POST | `/documents/:id/versions` | edit or owner (checked before the body is read) | multipart `file`. |
| DELETE | `/documents/:id` | owner | Soft delete: every grantee loses access immediately. |
| POST | `/documents/:id/restore` | owner | |
| GET | `/documents/:id/grants` | owner | Live and revoked grants (history). |
| POST | `/documents/:id/grants` | owner | `{ userId, permission: read|edit, expiresAt? }`. Not to yourself, not to admins, viewers read only, expiry ≤ 1 year. Re-sharing replaces (and records) the previous permission. |
| DELETE | `/documents/:id/grants/:grantId` | owner **of this document** | The grant must belong to `:id`; a grant id from another document → `404`. Immediate. |
| GET | `/documents/:id/activity` | owner | Last 200 audit entries for the document, including refusals. |

## People

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/users/directory` | role **owner** | `?q=`. Active non-admin users (id, name, email, role, department) for the share dialog. Max 25. |

## Administration (role **admin**, and the account gate)

Admins manage people and watch activity. They have **no document access level**: they cannot view or download content.

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/overview` | Counts, alerts (probing, bulk downloads, failed sign-ins, stale grants, orphaned documents), audit chain status. |
| GET | `/admin/audit` | `outcome`, `action`, `actor`, `document`, `before` (paging by entry number). 100 per page. |
| GET | `/admin/audit/verify` | Recomputes the whole HMAC chain: `{ ok, checked, brokenAt?, reason? }`. |
| GET | `/admin/documents` | Metadata of every document with grant, download and refusal counts. No content. |
| POST | `/admin/documents/:id/transfer` | `{ newOwnerId }`, an active **owner**. The old owner loses access immediately. |
| GET | `/admin/users` | Everyone, with roles, 2FA, verification and session counts. |
| POST | `/admin/users` | `{ email, name, role, department?, password }`. Password policy applies; the person must change it at first sign-in. |
| PATCH | `/admin/users/:id` | `{ isActive?, role? }`. Disabling ends all sessions. Role change blocked while they own documents. Not on yourself or demo accounts. |
| POST | `/admin/users/:id/reset-password` | `{ password }` temporary password; ends sessions; must be changed at next sign-in. Not on yourself or demo accounts. |
| POST | `/admin/users/:id/reset-mfa` | Clears the authenticator (lost phone); ends sessions. Not on yourself or demo accounts. |

## Health

| Method | Path | Notes |
|---|---|---|
| GET | `/healthz` | `{ ok: true }`, used by Render. |
