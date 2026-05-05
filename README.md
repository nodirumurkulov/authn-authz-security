Small Fastify + Prisma (SQLite) API demonstrating authentication, server-side sessions, RBAC, rate limiting, input validation, audit logging, and basic secret handling.

## Prerequisites

- Node.js 20+
- npm

## Version control

If `git init` fails on this path (some cloud-sync folders restrict `.git`), run Git from a clone elsewhere or adjust sync exclusions, then copy the project.

## Setup

```bash
cp .env.example .env
# Ensure SESSION_SECRET is at least 32 characters (example file is valid for local dev).
npm install
npx prisma migrate deploy
npm run db:seed
```

## Run

```bash
npm run dev
# or
npm run build && npm start
```

Default port: `3000` (override with `PORT` in `.env`).

## Demo accounts (after seed)

| Email               | Password      | Roles                          |
|---------------------|---------------|--------------------------------|
| admin@example.com   | AdminPass1!x  | admin, user                    |
| user@example.com    | UserPass1!x   | user                           |
| auditor@example.com | AuditPass1!x  | auditor_readonly               |

## API overview

- `GET /health` — liveness (no auth).
- `POST /auth/register` — create user (default role `user`).
- `POST /auth/login` — sets signed `httpOnly` session cookie `sid`.
- `POST /auth/logout` — clears session (requires auth).
- `GET /auth/me` — current user and roles.
- `PATCH /auth/password` — change password; ends all sessions (requires auth).
- `GET/POST/PATCH/DELETE /api/documents` — CRUD; owners see only their docs; `admin` can access any.
- `GET /api/audit/events` — recent audit rows (`admin`, `auditor_readonly`).
- `GET /api/admin/users` — list users (`admin` only).
- `POST /api/admin/users/:userId/roles` — assign role (`admin` only).

Use a cookie-aware client (browser, `curl -c/-b`, or Postman) for session auth.

Example:

```bash
curl -s -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"UserPass1!x"}' \
  http://localhost:3000/auth/login
curl -s -b cookies.txt http://localhost:3000/auth/me
```

## Security notes

- **Secrets**: Never commit `.env`. In production use a secrets manager (AWS Secrets Manager, GCP Secret Manager, Doppler, 1Password Secrets Automation, etc.) and inject env vars at runtime.
- **Cookies**: `sid` is `httpOnly`, `sameSite=lax`, and `secure` when `NODE_ENV=production`.
- **Sessions**: Opaque random token in DB; new login revokes prior sessions for that user.
- **Passwords**: Argon2id hashes only.
- **Authz**: Route guards plus object-level checks on documents (IDOR mitigation).
- **Validation**: Zod on mutating routes.
- **Rate limits**: Global limiter + stricter bucket on `/auth`; extra per-IP+email throttle on login failures.
- **Headers**: `@fastify/helmet` enabled (CSP disabled for simple JSON API clients).
- **CORS**: Set `CORS_ORIGINS` to a comma-separated allowlist for browser apps; empty means CORS disabled for cross-origin browsers.
- **CSRF**: Same-site cookie session reduces CSRF risk for same-site deployments. If you add a SPA on another origin, add CSRF tokens or use `SameSite=strict` with a BFF pattern—document your choice.
- **Dependencies**: Run `npm audit` regularly; enable Dependabot on the repo.

## Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md).

## Requirement map

| Concern              | Mechanism                                      | Where                          |
|----------------------|------------------------------------------------|--------------------------------|
| Authentication       | Argon2 + DB sessions + signed cookie           | `src/routes/auth.ts`, `sessionPlugin.ts` |
| Authorization        | RBAC + document ownership                      | `src/auth/guards.ts`, `routes/documents.ts`, `admin.ts` |
| Session hygiene      | Rotation on login; password change revokes all | `routes/auth.ts`               |
| Rate limiting        | `@fastify/rate-limit` + login throttle         | `src/index.ts`, `routes/auth.ts` |
| Server validation    | Zod                                            | Route files                    |
| Audit                | `AuditEvent` rows                              | `src/lib/audit.ts`, routes     |
