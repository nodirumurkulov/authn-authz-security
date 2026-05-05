# 10-Minute Walkthrough

Use this script when you want to understand the app quickly or record a demo.

## 1) Setup

```bash
cp .env.example .env
npm install
npx prisma migrate deploy
npm run db:seed
npm run dev
```

## 2) Login and inspect your session identity

```bash
curl -s -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"'"$SEED_USER_PASSWORD"'"}' \
  http://localhost:3000/auth/login

curl -s -b cookies.txt http://localhost:3000/auth/me
```

Expected: `200` and user role `user`.

## 3) Create a user-owned document

```bash
curl -s -b cookies.txt -H "Content-Type: application/json" \
  -d '{"title":"My private doc","body":"Only me or admin should read this."}' \
  http://localhost:3000/api/documents
```

Keep the returned `id` as `DOC_ID`.

## 4) Show object-level authorization (IDOR protection)

Login as another non-admin user:

```bash
curl -s -c other.txt -H "Content-Type: application/json" \
  -d '{"email":"auditor@example.com","password":"'"$SEED_AUDITOR_PASSWORD"'"}' \
  http://localhost:3000/auth/login
```

Try to read the first user's document:

```bash
curl -i -s -b other.txt http://localhost:3000/api/documents/DOC_ID
```

Expected: `403 Forbidden` (non-owner cannot access it).

## 5) Show admin override (intended behavior)

```bash
curl -s -c admin.txt -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"'"$SEED_ADMIN_PASSWORD"'"}' \
  http://localhost:3000/auth/login

curl -i -s -b admin.txt http://localhost:3000/api/documents/DOC_ID
```

Expected: `200 OK` for admin.

## 6) Show audit trail

```bash
curl -s -b admin.txt http://localhost:3000/api/audit/events?limit=20
```

Expected actions include login events and document operations.

## 7) Show session invalidation after password change

```bash
curl -s -b cookies.txt -H "Content-Type: application/json" \
  -d '{"currentPassword":"'"$SEED_USER_PASSWORD"'","newPassword":"NewPass12345!"}' \
  http://localhost:3000/auth/password

curl -i -s -b cookies.txt http://localhost:3000/auth/me
```

Expected: second request should no longer be authorized until login again.
