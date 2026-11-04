# TrustVault architecture

Diagrams of how TrustVault is put together and how it decides who can reach a document.
Every box below maps to real code; file names are given so each claim can be checked.

1. [System overview](#1-system-overview)
2. [Request pipeline](#2-request-pipeline)
3. [Downloading a document, step by step](#3-downloading-a-document-step-by-step)
4. [The access decision](#4-the-access-decision)
5. [Data model](#5-data-model)
6. [Signing in](#6-signing-in)
7. [Revocation](#7-revocation)
8. [The tamper-evident audit chain](#8-the-tamper-evident-audit-chain)

---

## 1. System overview

```mermaid
flowchart LR
    U["Browser<br/>vanilla JS, strict CSP"] -->|HTTPS| CF["Cloudflare edge<br/>TLS, HTTP to HTTPS"]
    CF --> R["Render web service<br/>Singapore"]
    subgraph APP["Node.js 24 + Express 5 (src/)"]
        direction TB
        MW["Middleware<br/>headers, rate limit, Origin,<br/>session, CSRF"]
        AZ["authz.js<br/>the ONLY document<br/>access decision"]
        RT["Routes<br/>documents, admin, users, auth"]
        AU["audit.js<br/>HMAC-chained log"]
        MW --> RT --> AZ
        RT --> AU
    end
    R --> APP
    APP -->|"TLS, certificate verified"| DB[("Neon PostgreSQL<br/>users, grants, documents,<br/>encrypted files, audit log")]
    APP -->|HTTPS API| MAIL["Brevo<br/>one-time email codes"]
    ENV["Render environment<br/>FILE_ENCRYPTION_KEY<br/>AUDIT_HMAC_KEY"] -. secrets never in DB or git .-> APP
```

- **No file system storage.** File bytes are AES-256-GCM encrypted and stored in
  `document_versions.ciphertext`; there is no path a web server could serve.
- **Keys live apart from data.** The encryption and HMAC keys are host environment variables,
  so a copy of the database alone cannot decrypt files or forge audit entries.
- **Locally and in tests** the same code runs on PGlite (PostgreSQL compiled to WebAssembly),
  so the triggers and SQL are identical to production.

## 2. Request pipeline

Order matters: every `/api` request passes these layers before any handler runs (`src/app.js`).

```mermaid
flowchart TD
    A["Request"] --> B["Security headers<br/>CSP, HSTS, X-Frame-Options, nosniff"]
    B --> C["Rate limit<br/>300 req/min per IP"]
    C --> D["JSON body, 32 KB max"]
    D --> E{"Origin header<br/>from another site?"}
    E -->|yes| X1["403"]
    E -->|no| F["loadSession<br/>hash cookie, look up in DB,<br/>check active, idle and expiry"]
    F --> G{"State-changing request<br/>without the right<br/>X-CSRF-Token?"}
    G -->|yes| X2["403"]
    G -->|no| H{"Signed in?"}
    H -->|"no, and route needs it"| X3["401"]
    H -->|yes| I{"Must change password,<br/>or admin without 2FA?"}
    I -->|yes| X4["403 + code<br/>only /auth/* allowed"]
    I -->|no| J["requireRole / requireDocAccess"]
    J -->|refused| X5["404 or 403<br/>+ audit row 'denied'"]
    J -->|allowed| K["Handler<br/>change + audit row in ONE transaction"]
    K --> L["Response"]
```

## 3. Downloading a document, step by step

What the interview question "where is the authorisation decision made when someone downloads
a file?" refers to (`src/routes/documents.js` → `src/authz.js`).

```mermaid
sequenceDiagram
    autonumber
    actor V as Vik (viewer)
    participant API as Express route<br/>GET /documents/:id/download
    participant AZ as authz.js<br/>requireDocAccess('download')
    participant DB as PostgreSQL
    participant AU as audit.js

    V->>API: GET /api/documents/{id}/download (session cookie)
    API->>AZ: before the handler runs
    AZ->>DB: SELECT document by id
    AZ->>DB: SELECT live grant (not revoked, not expired) for Vik
    alt no live grant, deleted, admin, or unknown id
        AZ->>AU: append 'document.download' outcome=denied
        AZ-->>V: 404 Document not found (same answer as "does not exist")
    else read, edit or owner
        AZ->>API: req.doc, req.docLevel
        API->>DB: SELECT encrypted version
        API->>API: AES-256-GCM decrypt (doc id + version bound as AAD), check SHA-256
        API->>AU: append 'document.download' outcome=ok (BEFORE sending)
        API-->>V: file bytes: attachment, nosniff, CSP sandbox, no-store
    end
```

If `requireDocAccess('download')` is removed from that route, anyone with a session gets
any file, and 12 of the 83 tests fail.

## 4. The access decision

`effectiveAccess()` and `authorizeDoc()` in `src/authz.js`. Anything not explicitly allowed is denied.

```mermaid
flowchart TD
    S(["user, document id, action"]) --> A{"User active and<br/>id a valid UUID?"}
    A -->|no| DENY
    A -->|yes| B{"Document exists?"}
    B -->|no| DENY
    B -->|yes| C{"Role is admin?"}
    C -->|yes| DENY
    C -->|no| D{"User is the owner?"}
    D -->|yes| OWN["level = owner"]
    D -->|no| E{"Document in trash?"}
    E -->|yes| DENY
    E -->|no| F{"Live grant?<br/>not revoked, not expired"}
    F -->|no| DENY
    F -->|yes| G{"Role is viewer?"}
    G -->|yes| RD["level = read<br/>(edit grant capped)"]
    G -->|no| GR["level = grant permission<br/>read or edit"]
    OWN --> H{"Level high enough<br/>for the action?"}
    RD --> H
    GR --> H
    H -->|no| DENY
    H -->|yes| T{"In trash and action is<br/>not view or restore?"}
    T -->|yes| DENY
    T -->|no| ALLOW(["ALLOW"])
    DENY(["DENY: audit 'denied', return 404"])
```

| Level | Allows |
|---|---|
| `read` | view metadata, list versions, download |
| `edit` | read + rename, re-describe, re-categorise, upload a new version |
| `owner` | edit + delete, restore, share, revoke, see grants, see activity |

## 5. Data model

Full definition in [`db/schema.sql`](../db/schema.sql).

```mermaid
erDiagram
    users ||--o{ sessions : "signs in with"
    users ||--o{ documents : owns
    users ||--o{ grants : "is granted"
    documents ||--o{ grants : "shared through"
    documents ||--|{ document_versions : "has versions"
    users ||--o{ mfa_recovery_codes : has
    users ||--o{ pending_logins : "mid sign-in"
    users ||--o{ otp_codes : "receives"

    users {
        uuid id PK
        text email UK
        text role "admin | owner | viewer"
        text password_hash "scrypt"
        bool is_active
        bool mfa_enabled
        text mfa_secret_enc "AES-GCM encrypted"
        bool email_verified
    }
    sessions {
        text token_hash PK "SHA-256 of cookie"
        uuid id "public id for sign-out"
        uuid user_id FK
        text csrf_token
        timestamptz expires_at
    }
    documents {
        uuid id PK
        uuid owner_id FK
        text title
        text category
        int current_version
        timestamptz deleted_at "soft delete"
    }
    document_versions {
        uuid id PK
        uuid document_id FK
        int version
        bytea ciphertext "AES-256-GCM"
        text sha256
    }
    grants {
        uuid id PK
        uuid document_id FK
        uuid grantee_id FK
        text permission "read | edit"
        timestamptz expires_at
        timestamptz revoked_at "never deleted: history"
    }
    audit_log {
        bigserial seq PK
        timestamptz at
        text actor_email
        text action
        text outcome "ok | denied | error"
        text prev_hash
        text hash "HMAC chain"
    }
    otp_codes {
        uuid id PK
        text ticket_hash
        text code_hash "HMAC, never the code"
        int attempts
        timestamptz expires_at
    }
```

`audit_log` is deliberately unlinked by foreign keys, so evidence survives anything that
happens to users or documents. Triggers reject `UPDATE`, `DELETE` and `TRUNCATE` on it.

## 6. Signing in

`src/auth.js`. A session is created only after every required factor is proven.

```mermaid
stateDiagram-v2
    [*] --> FirstFactor
    FirstFactor --> CheckEmail: password correct, or email code correct
    FirstFactor --> FirstFactor: wrong (throttled, same error for unknown email)
    CheckEmail --> VerifyEmail: email not verified yet
    VerifyEmail --> CheckSecond: 6-digit code from email
    CheckEmail --> CheckSecond: verified
    CheckSecond --> Session: no authenticator set up
    CheckSecond --> SecondFactor: authenticator enabled
    SecondFactor --> Session: TOTP code (no replay) or one-time recovery code
    SecondFactor --> [*]: 5 wrong attempts, ticket burned
    Session --> Gated: must change password, or admin without 2FA
    Gated --> Session: fixed on the account page
    Session --> [*]: logout, 30 min idle, 8 h max, disabled, or password changed elsewhere
```

## 7. Revocation

Why "taking access away" works on the very next request: nothing that outlives the decision
is ever issued (no signed URLs, no JWTs, no cached permissions).

```mermaid
sequenceDiagram
    autonumber
    actor O as Olivia (owner)
    participant S as Server
    participant DB as PostgreSQL
    actor V as Vik (viewer)

    V->>S: download
    S->>DB: live grant for Vik? yes
    S-->>V: 200 file (audited)
    O->>S: DELETE /documents/{id}/grants/{grantId}
    S->>DB: UPDATE grants SET revoked_at = now() (+ audit row, same transaction)
    S-->>O: 200 revoked
    V->>S: download again, same session, one second later
    S->>DB: live grant for Vik? no (revoked_at is set)
    S-->>V: 404 (audited as denied)
```

Disabling a user deletes every session row and is also re-checked on every request; deleting
a document, an expired grant and an ownership transfer all take effect the same way.

## 8. The tamper-evident audit chain

`src/audit.js`. Each row's hash covers the previous row's hash, with a key that is not in the
database.

```mermaid
flowchart LR
    G["genesis<br/>000…0"] --> R1["row 1<br/>hash1 = HMAC(key, genesis | row 1)"]
    R1 --> R2["row 2<br/>hash2 = HMAC(key, hash1 | row 2)"]
    R2 --> R3["row 3<br/>hash3 = HMAC(key, hash2 | row 3)"]
    R3 --> RN["…"]
    V{{"verifyChain()<br/>recompute every hash"}} -.-> R1 & R2 & R3
```

| Attack | Result |
|---|---|
| `UPDATE` / `DELETE` / `TRUNCATE` through SQL | Rejected by database triggers |
| Disable triggers, then edit a row | That row's hash no longer matches: reported at that entry |
| Delete a row | The next row's `prev_hash` points at nothing: reported at the next entry |
| Insert a forged row | Cannot compute a valid HMAC without the key: reported |
| Steal the database **and** the server's key | Not prevented: listed as accepted risk T-17b in THREATS.md |
