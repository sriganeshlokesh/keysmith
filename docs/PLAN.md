# Keysmith — Drafted Auth Service — Master Plan

> Plan for Claude Code. Work through phases in order, one phase per session where possible.
> Each phase has acceptance criteria — do not move on until they pass.
> Owner: Sri. Project: Drafted (AI-powered resume optimization). Existing backend service: forged (Go, separate repo).
>
> This is the authoritative copy of the plan (adapted from the original draft in
> `~/Downloads/drafted-auth-master-plan.md`). Update acceptance-criteria status here as phases complete.

---

## 0. Locked Decisions (do not revisit)

| Area | Decision |
|---|---|
| Build approach | Roll our own auth service in Go (no Clerk/Auth0/Ory) |
| Auth methods (v1) | Google OIDC, LinkedIn OIDC, email + password — all three in v1 |
| OAuth flow | Authorization Code + PKCE for both providers |
| Password hashing | argon2id |
| Session model | 15-min access JWT (SPA holds in memory only) + rotating refresh token in httpOnly cookie |
| Refresh security | Token families with reuse detection; hashed at rest (SHA-256) |
| Signing | Ed25519; public keys served via JWKS endpoint |
| Token validation in forged | Local/stateless via shared `authkit` package (JWKS cache); no runtime calls to auth |
| Claims | `sub`, `email`, `iss`, `aud`, `exp`, `iat` only. `aud="forge"`. No profile/role data in JWT |
| Identity key | `users.id` (uuid) == JWT `sub` == FK for all user-owned data in forged |
| Database | PostgreSQL on Railway (prod/staging); Docker Compose Postgres for local dev; Neon free tier optional for migration testing |
| Account linking | Auto-link OAuth identity to existing user only when provider email is verified and matches. Never auto-link unverified email |
| Email provider | Resend (verification + password reset) |
| Repo structure | **Standalone repo `keysmith`** holding all backend auth work: the auth service plus the nested `pkg/authkit` module. No monorepo. `forged` (backend) and `drafted` (SPA) stay in their own repos |
| Service naming | Frontend = **drafted**, backend = **forged**, auth service = **keysmith** (this repo; supersedes the earlier "signed" name) |
| Frontend | React SPA (Vite), in the `drafted` repo |

---

## 1. Repo Layout & Architecture

Keysmith follows the **hexagonal (ports & adapters) architecture, mirroring forged's conventions**
(itself modeled on [go-hexagonal](https://github.com/RanchoCooper/go-hexagonal)):

- **domain/** — entities (`model`), repository ports (`repo`), domain services (`service`). No transport or persistence concerns.
- **application/** — one package per area (e.g. `password`, `token`, `oauth`), each exposing a use case implementing `application/core` contracts. Dependencies are declared as interfaces at the consumer.
- **adapter/** — implementations of the ports: `repository/postgres` (pgx), `email` (Resend), `oidc` (providers). `adapter/dependency` is the **Wire composition root** — the only adapter package allowed to import `api/*`. Workflow: edit `wire.go` → `make wire` → commit `wire_gen.go` (CI checks staleness).
- **api/** — chi router, `handle` (HTTP handlers), `dto`, `middleware`. Router/handlers declare the interfaces they consume; Wire binds them (`wire.Bind`).

```
keysmith/
├── go.work                      # ties the root module + pkg/authkit for local dev
├── go.mod                       # module github.com/sriganeshlokesh/keysmith (wire via go tool)
├── docker-compose.yml           # local Postgres + mailpit for email testing
├── Makefile                     # dev, test, lint, wire, migrate targets
├── .github/workflows/ci.yml     # build, vet, wire-staleness, test, golangci-lint
├── cmd/main.go                  # config → logger → dependency.InitializeServer → graceful shutdown
├── config/                      # env parsing (fail fast)
├── util/log/                    # slog JSON logger factory
├── api/
│   ├── dto/                     # request/response bodies
│   └── http/                    # router.go, server.go
│       ├── handle/              # HTTP handlers (health; auth handlers per phase)
│       └── middleware/          # request logger; CORS/rate limits per phase
├── application/
│   └── core/                    # Input/Output/UseCase contracts (areas arrive per phase)
├── domain/
│   ├── model/                   # entities (Phase 1)
│   ├── repo/                    # repository ports (Phase 1)
│   └── service/                 # rotation/reuse rules (Phase 2)
├── adapter/
│   ├── dependency/              # wire.go, providers.go, wire_gen.go (committed)
│   └── repository/postgres/     # pgx pool + repositories (Phase 1)
├── migrations/                  # goose SQL migrations
├── docs/PLAN.md                 # this file
└── pkg/authkit/                 # nested module: HTTP middleware, gRPC interceptor, JWKS cache, dev mode
    └── go.mod                   # module github.com/sriganeshlokesh/keysmith/pkg/authkit
```

Future adapters land in their phase: `adapter/email` (Phase 3), `adapter/oidc` (Phase 4).
Application areas: `application/password` (Phase 3), `application/token` (Phase 2), `application/oauth` (Phase 4).

**authkit as a nested module:** forged imports `github.com/sriganeshlokesh/keysmith/pkg/authkit` without inheriting the auth service's dependency graph (pgx, oauth2, resend, …). Version it with prefixed tags (`pkg/authkit/v0.1.0`); until first tag, forged can pin `@main`.

## 2. Tech Stack

- Go 1.26+, `chi` router
- `jackc/pgx/v5` (pgxpool) — max 10 conns per service
- `pressly/goose/v3` for migrations (SQL files)
- `coreos/go-oidc/v3` + `golang.org/x/oauth2` for Google/LinkedIn
- `alexedwards/argon2id` for password hashing
- `golang-jwt/jwt/v5` for signing (Ed25519); `lestrrat-go/jwx/v3` `jwk.Cache` in authkit for JWKS fetching (v2 is deprecated upstream)
- `resend/resend-go` for email
- `golang.org/x/time/rate` for in-memory rate limiting (v1; Redis-backed later if multi-instance)
- Local email testing: mailpit container (SMTP catch-all UI) OR Resend test mode

---

## 3. Railway PostgreSQL — Manual Setup (performed by Sri, not Claude Code)

> Claude Code: treat this section as documentation of the environment. Do not attempt these steps; assume `DATABASE_URL` exists when writing code. UI labels may drift — verify in the Railway dashboard.

### 3.1 Provision

1. Create/open the Railway project (name it `drafted`).
2. In the project canvas: **New → Database → Add PostgreSQL**. This creates a Postgres service backed by a persistent volume.
3. Wait for deploy to finish, then open the Postgres service → **Variables** tab. Railway generates:
   - `DATABASE_URL` — **private-network** URL (host like `postgres.railway.internal`). Only reachable from services in the same project + environment. Uses Railway's internal IPv6 network. Free of egress fees. **Use this for keysmith/forged in production.**
   - `DATABASE_PUBLIC_URL` — public TCP-proxy URL (host like `xxxx.proxy.rlwy.net:PORT`). Reachable from anywhere. Incurs egress fees and is slower. **Use only for running migrations/psql from your laptop or CI.**
   - `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` — individual components.

### 3.2 Wire the auth service to the DB

1. Deploy the auth service in the same project (New → GitHub Repo → select `keysmith`; repo root is the service root). The build uses the repo `Dockerfile` (pinned via `railway.toml`, mirroring forged) — Railpack's Go autodetection fails on the `cmd/` layout.
2. In the keysmith service → Variables, add a **reference variable** instead of pasting the string:
   ```
   DATABASE_URL=${{Postgres.DATABASE_URL}}
   ```
   (Replace `Postgres` with the actual service name if renamed.) Reference variables stay correct if credentials rotate.
3. Repeat for forged when it needs DB access.
4. Private-network note: internal DNS resolves over IPv6. pgx handles this fine; if a client library fails to resolve `*.railway.internal`, it's usually an IPv4-only resolver — flag it rather than switching to the public URL.

### 3.3 Least-privilege app user (recommended)

Railway gives you a superuser-ish default role. Create a scoped role for the app:

```bash
# from your laptop
psql "$DATABASE_PUBLIC_URL"
```
```sql
CREATE ROLE auth_app LOGIN PASSWORD '<generate-strong-password>';
GRANT CONNECT ON DATABASE railway TO auth_app;
GRANT USAGE ON SCHEMA public TO auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_app;
```
Run migrations as the default (owner) role; run the app as `auth_app` (compose a second URL with the same host but `auth_app` credentials and set that as the service's `DATABASE_URL`).

### 3.4 Backups — do this on day one

1. Open the Postgres service → the attached **volume** → **Backups** tab.
2. Enable a **daily** backup schedule. Confirm retention settings.
3. **Test a restore once** into a scratch environment before real users exist — an untested backup is not a backup.
4. Belt-and-suspenders: add a weekly `pg_dump` via cron (GitHub Actions is fine) using `DATABASE_PUBLIC_URL`, pushed to an S3/R2 bucket:
   ```bash
   pg_dump --format=custom "$DATABASE_PUBLIC_URL" > drafted-$(date +%F).dump
   ```

### 3.5 Environments

1. In the Railway project, create a **staging** environment (Environments → New). Railway duplicates services; the staging Postgres is a separate instance with its own volume.
2. Point staging services at staging DB via the same `${{Postgres.DATABASE_URL}}` reference (references resolve per-environment).
3. Optional: enable PR environments later.

### 3.6 Operational settings

- **Connections:** keep pgxpool `MaxConns` at ~10 per service. Railway Postgres is a single instance; no bundled pooler like pgbouncer, so total connections across services + psql sessions must stay comfortably under the instance's `max_connections` (check with `SHOW max_connections;`).
- **TLS:** public proxy URL — use `sslmode=require`. Private URL — internal network; if TLS isn't enabled on the internal listener, `sslmode=disable` is acceptable there (traffic never leaves Railway's private network).
- **Monitoring:** Postgres service → Metrics tab (CPU/RAM/disk). Set a usage/spend alert in project settings.
- **Extensions:** run `CREATE EXTENSION IF NOT EXISTS citext;` — this is in migration 0001; confirm the Railway image ships citext (it's in contrib, should be present).

### 3.7 Local development

Do **not** develop against Railway. Use Docker Compose (`docker-compose.yml` in this repo): `postgres:16` (user/pass/db `keysmith`, host port **5433** since 5432 is taken by other local DBs) + mailpit (UI on :8025, SMTP on :1025).

`DATABASE_URL=postgres://keysmith:keysmith@localhost:5433/keysmith?sslmode=disable`

Optional: use Neon's free tier as a scratch environment for testing migrations against a fresh branch before applying to Railway staging.

### 3.8 Running migrations against Railway

From laptop or CI (never bake into app startup for prod):
```bash
goose -dir migrations postgres "$DATABASE_PUBLIC_URL" up
```
For local dev, `make migrate-up` targets the compose DB. App startup MAY auto-migrate in local dev only, gated by `AUTO_MIGRATE=true` (only honored when `ENV=local`).

---

## 4. Database Schema (migration 0001)

```sql
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
```

Cleanup job (in-process ticker, nightly): delete expired/consumed `one_time_tokens` and expired/revoked `refresh_tokens` older than 30 days.

---

## 5. Token & Rotation Rules

- **Access JWT:** Ed25519-signed, TTL 15m, header `kid` set. Claims: `sub`, `email`, `iss=https://auth.<domain>`, `aud=forge`, `exp`, `iat`, `jti`.
- **Refresh token:** 256-bit random, base64url, TTL 30d, delivered ONLY as cookie: `HttpOnly; Secure; SameSite=Lax; Path=/auth; Domain=<auth host>`.
- **Rotation:** every `/auth/refresh` issues a new refresh token in the same `family_id`, sets `replaced_by` on the old row.
- **Reuse detection:** if a presented token's row has `replaced_by` set or `revoked_at` set → revoke entire family, return 401, log security event.
- **Logout:** revoke presented token's family, clear cookie.
- **Key rotation:** support multiple active keys; JWKS serves all valid public keys; sign with newest. Keys supplied via env (`AUTH_SIGNING_KEYS`, JSON array of {kid, private key}) — no key material in DB or repo. Dev mode uses a checked-in dev keypair, enabled only when `ENV=local`.

## 6. HTTP API (auth service)

| Method | Path | Notes |
|---|---|---|
| GET | `/auth/{provider}/login` | provider ∈ google, linkedin. Sets state+PKCE cookie, 302 to provider |
| GET | `/auth/{provider}/callback` | validate state/nonce, exchange code, verify ID token, upsert identity, apply linking rules, set refresh cookie, 302 to SPA `/auth/complete` |
| POST | `/auth/signup` | email+password; create user + credential; send verify email |
| POST | `/auth/login` | password check; require generic error on failure (no user enumeration) |
| POST | `/auth/verify-email` | body: token |
| POST | `/auth/request-password-reset` | always 200 regardless of account existence |
| POST | `/auth/reset-password` | body: token + new password; revokes all refresh families |
| POST | `/auth/refresh` | cookie in → new access JWT (JSON) + rotated cookie |
| POST | `/auth/logout` | revoke family, clear cookie |
| GET | `/auth/me` | requires access JWT; returns user profile |
| GET | `/.well-known/jwks.json` | public keys; Cache-Control: max-age=300 |
| GET | `/healthz` | liveness + DB ping |

**OAuth-per-provider config:** Google issuer `https://accounts.google.com`, scopes `openid email profile`. LinkedIn: OIDC ("Sign In with LinkedIn using OpenID Connect" product must be enabled on the LinkedIn app), scopes `openid profile email`. LinkedIn's OIDC discovery/ID-token behavior has quirks — verify discovery URL and whether `nonce` is honored during implementation; fall back to userinfo endpoint if ID token claims are thin.

**Linking rules (callback):**
1. Identity exists → login as that user.
2. No identity, provider email verified AND matches existing user → create identity, link, login.
3. No identity, provider email unverified → create identity + NEW user (never auto-link), mark email_verified=false.
4. No identity, no matching user → create user (email_verified from provider claim) + identity.

## 7. authkit (pkg/authkit)

- `Middleware(cfg)` — net/http middleware: extract Bearer token, validate sig via cached JWKS (refresh on unknown `kid`, min refresh interval 5m), validate `iss`/`aud`/`exp` with 30s leeway, inject user into context.
- `UnaryInterceptor(cfg)` — same for gRPC metadata `authorization`.
- `UserID(ctx) string`, `Email(ctx) string` accessors.
- Dev mode: `cfg.DevKey` static public key, no network.
- Zero dependencies on auth service internals. Table-driven tests with generated keypairs: expired token, wrong aud, wrong iss, unknown kid, garbage token, clock skew boundary.
- Nested module (`github.com/sriganeshlokesh/keysmith/pkg/authkit`) so forged imports it without keysmith's dependency graph.

## 8. SPA Integration (drafted repo)

- `AuthProvider` context: access token in memory only (never localStorage/sessionStorage).
- On app load: call `/auth/refresh` (credentials: include) to bootstrap a session; 401 → logged out state.
- Fetch wrapper: on 401 from forged, single-flight refresh then retry once.
- Login page: Google button, LinkedIn button (both = redirect to `/auth/{provider}/login`), email/password form, signup, forgot-password.
- `/auth/complete` route: lands after OAuth redirect, calls `/auth/refresh`, routes into app.
- CORS on auth service: allow SPA origin, `Access-Control-Allow-Credentials: true`, never `*`.

## 9. Phases & Acceptance Criteria

**Phase 0 — Scaffolding.** Hexagonal skeleton (mirroring forged), go.work, docker-compose (postgres + mailpit), Makefile (`dev`, `test`, `lint`, `wire`, `migrate-up/down`), Wire composition root, CI (build/vet/wire-staleness/test + golangci-lint). ✅ `make dev` boots keysmith against local Postgres; `/healthz` returns 200. — **Status: ✅ complete (2026-07-09)**

**Phase 1 — Schema + store layer.** Migration 0001; entities in `domain/model`, ports in `domain/repo`, pgx repositories in `adapter/repository/postgres` with integration tests against compose Postgres (`make test-integration`; CI runs them via a postgres service container). ✅ CRUD tests pass; goose up/down idempotent. — **Status: ✅ complete (2026-07-09)**

**Phase 2 — Token core.** Ed25519 keys from env, mint/verify, JWKS endpoint, refresh issue/rotate/reuse-detect (`domain/service` signer + `application/token`), nightly cleanup job (`adapter/job`). ✅ Unit tests incl. reuse → family revoked; JWKS parses with jwx. — **Status: ✅ complete (2026-07-09)**

**Phase 3 — Password auth.** signup/login/verify/reset endpoints (`application/password`, handlers in `api/http/handle`), argon2id, Resend client in `adapter/email` (mailpit in dev), rate limits (per-IP: 10/min login, 3/min signup & reset). ✅ Full flow test: signup → verify email link → login → refresh → me → logout. Password reset revokes all sessions. No user enumeration (identical responses/timing on unknown email). — **Status: not started**

**Phase 4 — OIDC.** Generic provider adapter in `adapter/oidc` + `application/oauth`, Google + LinkedIn configs, state+PKCE+nonce, callback with linking rules. ✅ Manual E2E with real Google/LinkedIn test apps; linking rules covered by unit tests with a fake provider. — **Status: not started**

**Phase 5 — authkit + forged.** Build authkit here; wire forged middleware/interceptor in the forged repo, protect routes, use `sub` as user FK. ✅ forged rejects bad/expired tokens locally with no auth-service calls; dev mode works offline. — **Status: not started**

**Phase 6 — SPA (drafted repo).** AuthProvider, login/signup UI, silent refresh, protected routes. ✅ Full browser flow for all three methods; hard-refresh keeps session via cookie bootstrap. — **Status: not started**

**Phase 7 — Hardening + deploy.** Structured logging (slog) with security events, request IDs, CORS lockdown, security headers, Railway deploy of keysmith (staging then prod), secrets in Railway variables, smoke tests. ✅ Staging E2E green; JWKS reachable by forged over private network; backups verified (§3.4). — **Status: not started**

## 10. Environment Variables (auth service)

```
ENV=local|staging|production
PORT=8080
SERVICE_NAME=keysmith
LOG_LEVEL=info
HTTP_READ_TIMEOUT=10s / HTTP_WRITE_TIMEOUT=30s / HTTP_IDLE_TIMEOUT=120s / SHUTDOWN_TIMEOUT=5s
DATABASE_URL=
PUBLIC_BASE_URL=https://auth.<domain>       # issuer + OAuth redirect base
SPA_ORIGIN=https://app.<domain>
AUTH_SIGNING_KEYS=                          # JSON [{"kid":"2026-07","private_key_b64":"..."}]
GOOGLE_CLIENT_ID= / GOOGLE_CLIENT_SECRET=
LINKEDIN_CLIENT_ID= / LINKEDIN_CLIENT_SECRET=
RESEND_API_KEY=
EMAIL_FROM=Drafted <no-reply@<domain>>
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=720h
AUTO_MIGRATE=false
```

## 11. Security Checklist (verify before prod)

- [ ] Refresh cookie: HttpOnly, Secure, SameSite=Lax, Path=/auth
- [ ] Access token never persisted client-side
- [ ] argon2id params ≥ (memory=64MB, iterations=1–3, parallelism=2); benchmark ~100ms
- [ ] All secrets/tokens stored hashed; constant-time comparisons
- [ ] State + nonce + PKCE on every OAuth flow
- [ ] No auto-link on unverified provider email
- [ ] Generic errors on login/reset (no enumeration)
- [ ] Rate limiting on all credential endpoints
- [ ] Password reset revokes all refresh families
- [ ] CORS: exact SPA origin, credentials allowed, no wildcard
- [ ] Security headers (HSTS, nosniff, frame-deny) on auth responses
- [ ] Railway backups enabled AND restore tested
- [ ] Least-privilege DB role for app runtime (§3.3)

## 12. Working Agreement for Claude Code

- One phase per session; read this file + relevant code before writing.
- Follow the hexagonal layering (§1) and forged's conventions: consumer-declared interfaces, Wire bindings in `adapter/dependency` only. After editing `wire.go`, run `make wire` and commit `wire_gen.go`.
- Write tests alongside code; run `make test` before declaring a phase done.
- Never invent Railway/Resend/LinkedIn API details — if uncertain, check docs or ask.
- No secrets in code or migrations. Dev keypair only under `ENV=local` guard.
- Keep `authkit` dependency-free of auth internals.
- Update the phase status markers in this file as phases complete.
