-- TrustVault schema. Idempotent: safe to run on every boot.
-- Runs unchanged on PostgreSQL 15+ and on PGlite (Postgres compiled to WASM).

CREATE TABLE IF NOT EXISTS users (
  id             uuid PRIMARY KEY,
  email          text NOT NULL UNIQUE CHECK (email = lower(email)),
  name           text NOT NULL,
  role           text NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
  department     text,
  password_hash  text NOT NULL,
  is_active      boolean NOT NULL DEFAULT true,
  is_demo        boolean NOT NULL DEFAULT false,   -- seeded accounts listed in README
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- Authentication hardening (added 2026-11-04). ADD COLUMN IF NOT EXISTS keeps this idempotent.
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at timestamptz NOT NULL DEFAULT now();
-- TOTP secret, AES-256-GCM encrypted with the server key (never stored in plain text).
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_enc text;
-- Highest TOTP time-step accepted so far: a code can never be used twice.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_step bigint NOT NULL DEFAULT 0;

-- One-time recovery codes, stored as SHA-256 hashes.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  text NOT NULL,
  used_at    timestamptz,
  PRIMARY KEY (user_id, code_hash)
);

-- A password check that passed but still needs a second factor. Short-lived, limited
-- attempts, and only the hash of its token is stored.
CREATE TABLE IF NOT EXISTS pending_logins (
  token_hash  text PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  timestamptz NOT NULL,
  attempts    integer NOT NULL DEFAULT 0,
  ip          text
);

-- Server-side sessions. The cookie holds a random token; only its SHA-256 is stored,
-- so a leaked database row cannot be replayed as a cookie.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash    text PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  ip            text,
  user_agent    text
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
-- Public id so a user can list and end their own sessions without ever seeing a token hash.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS id uuid NOT NULL DEFAULT gen_random_uuid();

CREATE TABLE IF NOT EXISTS documents (
  id               uuid PRIMARY KEY,
  owner_id         uuid NOT NULL REFERENCES users(id),
  title            text NOT NULL,
  description      text NOT NULL DEFAULT '',
  category         text NOT NULL,
  current_version  integer NOT NULL DEFAULT 1,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz,
  deleted_by       uuid REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS documents_owner_idx ON documents(owner_id);

-- Every upload is a new immutable version. File bytes are AES-256-GCM encrypted
-- and live only in this table: there is no file path a web server could serve.
CREATE TABLE IF NOT EXISTS document_versions (
  id           uuid PRIMARY KEY,
  document_id  uuid NOT NULL REFERENCES documents(id),
  version      integer NOT NULL,
  filename     text NOT NULL,
  mime_type    text NOT NULL,
  size_bytes   integer NOT NULL,
  sha256       text NOT NULL,
  iv           bytea NOT NULL,
  auth_tag     bytea NOT NULL,
  ciphertext   bytea NOT NULL,
  uploaded_by  uuid NOT NULL REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (document_id, version)
);

-- Per-document grants to named people. Revocation sets revoked_at (never deletes)
-- so the history of who had access stays queryable.
CREATE TABLE IF NOT EXISTS grants (
  id           uuid PRIMARY KEY,
  document_id  uuid NOT NULL REFERENCES documents(id),
  grantee_id   uuid NOT NULL REFERENCES users(id),
  permission   text NOT NULL CHECK (permission IN ('read', 'edit')),
  granted_by   uuid NOT NULL REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  revoked_at   timestamptz,
  revoked_by   uuid REFERENCES users(id)
);
-- At most one live grant per person per document.
CREATE UNIQUE INDEX IF NOT EXISTS grants_one_live_idx
  ON grants(document_id, grantee_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS grants_grantee_idx ON grants(grantee_id);

-- Append-only, HMAC-chained audit log. See src/audit.js.
CREATE TABLE IF NOT EXISTS audit_log (
  seq             bigserial PRIMARY KEY,
  at              timestamptz NOT NULL,
  actor_id        uuid,
  actor_email     text,
  action          text NOT NULL,
  outcome         text NOT NULL CHECK (outcome IN ('ok', 'denied', 'error')),
  document_id     uuid,
  target_user_id  uuid,
  details         text NOT NULL DEFAULT '{}',
  ip              text,
  prev_hash       text NOT NULL,
  hash            text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS audit_doc_idx ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS audit_actor_idx ON audit_log(actor_id);

-- The application role can INSERT into audit_log but nothing can UPDATE, DELETE or
-- TRUNCATE it: these triggers fire for every role, including the table owner.
CREATE OR REPLACE FUNCTION audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only (% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_is_append_only();

DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_is_append_only();
