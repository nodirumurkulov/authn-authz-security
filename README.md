Small Fastify + Prisma (SQLite) API demonstrating authentication, server-side sessions, RBAC, rate limiting, input validation, audit logging, and basic secret handling.

- login + server-side sessions
- role-based access control (RBAC)
- secure API patterns (validation, rate limits, headers)
- audit logging for sensitive actions

## Quick start

### 1) Requirements

- Node.js 20+
- npm

### 2) Install and initialize

```bash
cp .env.example .env
npm install
npx prisma migrate deploy
npm run db:seed
```

### 3) Start the app

```bash
npm run dev
```

API runs on `http://localhost:3000` by default.  
To run production build:

```bash
npm run build
npm start
```

## Seeded users

After `npm run db:seed`, three users exist:

| Email | Roles |
|------|------|
| `admin@example.com` | `admin`, `user` |
| `user@example.com` | `user` |
| `auditor@example.com` | `auditor_readonly` |

Passwords come from env vars (`SEED_ADMIN_PASSWORD`, `SEED_USER_PASSWORD`, `SEED_AUDITOR_PASSWORD`).  
For local demo speed, `.env.example` includes placeholders you can replace.  
Do not use demo credentials in production.

## Main API endpoints

### Health

- `GET /health` - service health check

### Authentication / session

- `POST /auth/register` - create a new user (default role `user`)
- `POST /auth/login` - login and set signed `httpOnly` cookie (`sid`)
- `POST /auth/logout` - logout and clear session cookie (auth required)
- `GET /auth/csrf-token` - retrieve CSRF token for current session (auth required)
- `GET /auth/me` - current user and roles (auth required)
- `PATCH /auth/password` - change password, rotate session (auth required)

### Documents (protected)

- `GET /api/documents`
- `POST /api/documents`
- `GET /api/documents/:id`
- `PATCH /api/documents/:id`
- `DELETE /api/documents/:id`

Regular users can only access their own documents; `admin` can access all.

### Admin / audit

- `GET /api/admin/users` - list users with lockout status (`admin` only)
- `POST /api/admin/users/:userId/roles` - assign role, invalidates target sessions (`admin` only)
- `DELETE /api/admin/users/:userId/roles` - revoke role, invalidates target sessions (`admin` only)
- `POST /api/admin/users/:userId/unlock` - unlock a locked account, invalidates target sessions (`admin` only)
- `GET /api/audit/events` - read audit events (`admin` or `auditor_readonly`)

## Example: login with curl

Use a cookie-aware client (browser, Postman, or curl with cookie file):

```bash
# Login (returns csrfToken in response body)
curl -s -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"'"$SEED_USER_PASSWORD"'"}' \
  http://localhost:3000/auth/login

# Read profile (GET — no CSRF token needed)
curl -s -b cookies.txt http://localhost:3000/auth/me

# Create document (POST — CSRF token required)
CSRF=$(curl -s -b cookies.txt http://localhost:3000/auth/csrf-token | jq -r .csrfToken)
curl -s -b cookies.txt -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"title":"My doc"}' \
  http://localhost:3000/api/documents
```

## Security features included

- Argon2id password hashing
- server-side opaque sessions in DB
- signed `httpOnly` cookie, `SameSite=Lax`, `Secure` in production
- RBAC middleware and object-level checks (IDOR protection)
- Zod request validation
- CSRF protection via per-session synchronizer token (`x-csrf-token` header)
- account lockout after 5 failed login attempts (15 min cooldown)
- admin unlock endpoint for locked accounts
- global + auth route rate limiting
- security headers via `@fastify/helmet`
- session rotation on privilege changes (password change, role assignment/revocation, unlock)
- structured error handling with machine-readable error codes (`VALIDATION_ERROR`, `UNAUTHORIZED`, `NOT_FOUND`, etc.)
- `X-Request-Id` on every response for log correlation and incident tracing
- error logging with sensitive field sanitization (passwords, tokens, secrets redacted)
- global error handler that prevents stack trace / internal detail leakage
- audit logs for login, password, role, session rotation, and document actions

## Environment variables

See `.env.example`:

- `DATABASE_URL`
- `SESSION_SECRET` (minimum 32 chars)
- `NODE_ENV`
- `PORT`
- `CORS_ORIGINS`
- `SEED_ADMIN_PASSWORD`
- `SEED_USER_PASSWORD`
- `SEED_AUDITOR_PASSWORD`

## Error response format

All error responses follow a consistent structure:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input",
    "details": { "fields": { "email": ["Invalid email"] }, "formErrors": [] },
    "requestId": "a1b2c3d4e5f6..."
  }
}
```

| Field | Description |
|-------|-------------|
| `code` | Machine-readable error code for programmatic handling |
| `message` | Human-readable error description |
| `details` | Optional structured validation details (field-level errors) |
| `requestId` | Correlation ID — echoed from `X-Request-Id` header or auto-generated |

### Error code reference

| Code | HTTP | When |
|------|------|------|
| `VALIDATION_ERROR` | 400 | Request body or params fail Zod schema validation |
| `INVALID_PARAMETERS` | 400 | Route parameters (`:id`, `:userId`) fail validation |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password on login |
| `UNAUTHORIZED` | 401 | No valid session cookie or session expired |
| `PASSWORD_CHANGE_FAILED` | 401 | Current password incorrect during password change |
| `FORBIDDEN` | 403 | Authenticated but not authorized for this resource |
| `INSUFFICIENT_ROLE` | 403 | User lacks the required role (e.g. non-admin accessing admin routes) |
| `CSRF_TOKEN_MISSING` | 403 | State-changing request sent without `x-csrf-token` header |
| `CSRF_TOKEN_INVALID` | 403 | `x-csrf-token` header value does not match session token |
| `CSRF_SESSION_MISSING` | 403 | Session exists but has no CSRF token stored |
| `NOT_FOUND` | 404 | Requested resource (user, document, role assignment) does not exist |
| `CONFLICT` | 409 | Resource already exists (e.g. duplicate email on registration) |
| `REGISTRATION_FAILED` | 409 | Registration failed due to existing account |
| `ACCOUNT_LOCKED` | 423 | Account locked after too many failed login attempts |
| `RATE_LIMITED` | 429 | Request rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Unexpected server error (details are never exposed to client) |
| `SERVER_MISCONFIGURATION` | 500 | Missing expected database records (e.g. roles not seeded) |

## Project notes

- Never commit `.env` or real secrets.
- For production, use a managed secret store and HTTPS.
- If Git behaves oddly in cloud-sync folders, use a local clone path for development.

## Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md).

## Learn and present this project

- Step-by-step live demo script: [`docs/DEMO_WALKTHROUGH.md`](docs/DEMO_WALKTHROUGH.md)
- Architecture + security control mapping: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
