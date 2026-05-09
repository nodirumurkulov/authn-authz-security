# Threat model: secure-demo-app

**Scope:** JSON API with cookie-backed opaque sessions, SQLite + Prisma, RBAC (`admin`, `user`, `auditor_readonly`), document resources, and append-only-style audit events.

**Assumptions:** HTTPS in production; attackers can send arbitrary HTTP requests; DB and server filesystem are trusted; operators protect `SESSION_SECRET` and database backups.

## Assets

- User credentials and session tokens  
- User-owned documents  
- Role assignments (privilege state)  
- Audit trail integrity (detectability of sensitive actions)

## STRIDE summary

| Category            | Threat example                                      | Mitigations in this codebase |
|---------------------|-----------------------------------------------------|------------------------------|
| Spoofing            | Forged session cookie                               | Random 256-bit token; cookie signed with server secret; lookup only on server |
| Tampering           | Client changes `userId` in body to escalate       | Identity from session only; authorization uses `sessionUser.id` + roles |
| Repudiation         | Admin denies assigning a role                       | `role_assigned` and other actions logged with actor, IP, UA, timestamp |
| Information disclosure | Stack traces or user enumeration               | Generic errors on auth failures; no passwords in audit metadata |
| Denial of service   | Credential stuffing, API flood                    | Global rate limit; `/auth` sub-limit; login throttle by IP+email; account lockout after 5 failed attempts (15 min) |
| Elevation of privilege | User reads/writes another user’s document (IDOR) | Document routes check `doc.userId === sessionUser.id` unless `admin` |

## Focused abuse cases (recommended tests)

### 1. Broken object-level authorization (IDOR)

**Scenario:** Authenticated `user@example.com` calls `GET /api/documents/:id` for a document owned by another user.

**Expected:** HTTP 403 (or 404 if you prefer equal response shapes—this app returns 403 after “found” check).

**How to test:** Log in as `user`, list own documents, copy an `id` from seed as `admin` or create a doc as another user, then request that id.

### 2. Session theft / fixation

**Scenario:** Attacker obtains a valid `sid` cookie value.

**Expected:** Full account access until expiry or logout; new login from legitimate user invalidates older sessions (reduces concurrent abuse). Production should enforce HTTPS (`secure` cookie) and short session TTL if threat model requires it.

**Mitigations present:** `httpOnly`, `sameSite=lax`, session invalidation on password change and on re-login.

### 3. Brute force and credential stuffing

**Scenario:** High volume of `POST /auth/login` with password guesses.

**Expected:** 429 from global/`/auth` limiters and/or login-specific throttle; `login_rate_limited` audit event.

### 4. Account lockout – distributed brute force

**Scenario:** Attacker targets a single account from many IPs to bypass IP-based rate limiting.

**Expected:** After 5 consecutive failed login attempts, the account is locked for 15 minutes regardless of source IP. The server returns HTTP 423 with a generic message. A `dummyVerify()` call runs even for locked accounts to prevent timing side-channel leakage of lock state.

**Admin remediation:** `POST /api/admin/users/:userId/unlock` resets the counter and lock. The `account_locked` and `account_unlocked` audit events track the lifecycle.

**How to test:** Send 5 incorrect password attempts for a valid email, then attempt a correct login — expect 423. Use the admin unlock endpoint, then login — expect 200.

## Out of scope (for this demo)

- Full account recovery / email verification flows  
- Hardware security modules, WAF rules, bot management  
- Formal log integrity (hash-chained logs, WORM storage)  
- mTLS or service-to-service auth between internal components  

## Residual risks

- SQLite file permissions and backup handling remain an operational concern.  
- Signed cookies are not encrypted; payload is only an opaque id—avoid putting PII in cookies.  
- Auditors reading `/api/audit/events` generate `audit_log_read` entries; very high volume could grow the table quickly (operational monitoring).  

## Change control

When adding new sensitive actions, log them via `writeAudit`, extend this document with any new abuse cases, and add automated tests for authorization boundaries where practical.
