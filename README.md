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
- `GET /auth/me` - current user and roles (auth required)
- `PATCH /auth/password` - change password, revoke all sessions (auth required)

### Documents (protected)

- `GET /api/documents`
- `POST /api/documents`
- `GET /api/documents/:id`
- `PATCH /api/documents/:id`
- `DELETE /api/documents/:id`

Regular users can only access their own documents; `admin` can access all.

### Admin / audit

- `GET /api/admin/users` - list users (`admin` only)
- `POST /api/admin/users/:userId/roles` - assign role (`admin` only)
- `GET /api/audit/events` - read audit events (`admin` or `auditor_readonly`)

## Example: login with curl

Use a cookie-aware client (browser, Postman, or curl with cookie file):

```bash
curl -s -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"'"$SEED_USER_PASSWORD"'"}' \
  http://localhost:3000/auth/login

curl -s -b cookies.txt http://localhost:3000/auth/me
```

## Security features included

- Argon2id password hashing
- server-side opaque sessions in DB
- signed `httpOnly` cookie, `SameSite=Lax`, `Secure` in production
- RBAC middleware and object-level checks (IDOR protection)
- Zod request validation
- global + auth route rate limiting
- security headers via `@fastify/helmet`
- audit logs for login, password, role, and document actions

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

## Project notes

- Never commit `.env` or real secrets.
- For production, use a managed secret store and HTTPS.
- If Git behaves oddly in cloud-sync folders, use a local clone path for development.

## Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md).

## Learn and present this project

- Step-by-step live demo script: [`docs/DEMO_WALKTHROUGH.md`](docs/DEMO_WALKTHROUGH.md)
- Architecture + security control mapping: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Next roadmap

- Add MFA or step-up auth for sensitive actions
- Add account lockout and optional captcha on repeated login failures
- Add refresh-token style session rotation policy for longer-lived sessions
- Move from SQLite to PostgreSQL for multi-user concurrency
