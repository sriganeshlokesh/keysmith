-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          citext UNIQUE NOT NULL,
  email_verified boolean NOT NULL DEFAULT false,
  name           text,
  avatar_url     text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identities (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider         text NOT NULL CHECK (provider IN ('google','linkedin')),
  provider_user_id text NOT NULL,          -- OIDC 'sub' from the provider
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_user_id)
);
CREATE INDEX idx_identities_user_id ON identities(user_id);

CREATE TABLE password_credentials (
  user_id       uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,             -- argon2id encoded string
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  bytea NOT NULL UNIQUE,       -- sha256(raw token); raw never stored
  family_id   uuid NOT NULL,
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz,
  replaced_by uuid REFERENCES refresh_tokens(id)
);
CREATE INDEX idx_refresh_tokens_user   ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);

CREATE TABLE one_time_tokens (
  token_hash  bytea PRIMARY KEY,           -- sha256(raw token)
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     text NOT NULL CHECK (purpose IN ('email_verify','password_reset')),
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz
);

-- +goose Down
DROP TABLE one_time_tokens;
DROP TABLE refresh_tokens;
DROP TABLE password_credentials;
DROP TABLE identities;
DROP TABLE users;
DROP EXTENSION IF EXISTS citext;
