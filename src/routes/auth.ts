import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { prisma } from "../prisma.js";
import { hashPassword, verifyPassword, dummyVerify } from "../lib/password.js";
import { newSessionToken, hashSessionToken } from "../lib/sessionToken.js";
import { writeAudit } from "../lib/audit.js";
import { requireAuth } from "../auth/guards.js";
import { clearSessionCookie, setSessionCookie } from "../auth/sessionPlugin.js";

const SESSION_MS = 24 * 60 * 60 * 1000;
const SESSION_MAX_AGE_SEC = Math.floor(SESSION_MS / 1000);

const passwordPolicy = z
  .string()
  .min(10)
  .max(128)
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[0-9]/, "Password must contain at least one digit")
  .regex(/[^a-zA-Z0-9]/, "Password must contain at least one special character");

const registerSchema = z.object({
  email: z.string().email().max(320),
  password: passwordPolicy,
});

const loginSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(1).max(128),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: passwordPolicy,
});

type LoginBucket = { count: number; resetAt: number };
const loginBuckets = new Map<string, LoginBucket>();

const THROTTLE_CLEANUP_INTERVAL_MS = 60_000;
let throttleCleanupTimer: ReturnType<typeof setInterval> | null = null;

function startThrottleCleanup(): void {
  if (throttleCleanupTimer) return;
  throttleCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of loginBuckets) {
      if (now > bucket.resetAt) loginBuckets.delete(key);
    }
  }, THROTTLE_CLEANUP_INTERVAL_MS);
  throttleCleanupTimer.unref();
}

function loginThrottleAllow(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const b = loginBuckets.get(key);
  if (!b || now > b.resetAt) {
    loginBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (b.count >= max) return false;
  b.count += 1;
  return true;
}

const SESSION_PRUNE_INTERVAL_MS = 10 * 60_000;

function startSessionPrune(): void {
  const timer = setInterval(async () => {
    try {
      await prisma.session.deleteMany({ where: { expiresAt: { lt: new Date() } } });
    } catch {
      /* best-effort cleanup */
    }
  }, SESSION_PRUNE_INTERVAL_MS);
  timer.unref();
}

const authRoutes: FastifyPluginAsync<{ secureCookie: boolean }> = async (app, opts) => {
  startThrottleCleanup();
  startSessionPrune();

  app.post("/register", async (request, reply) => {
    const parsed = registerSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid input", details: parsed.error.flatten() });
    }
    const { email, password } = parsed.data;
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return reply.code(409).send({ error: "Registration failed" });
    }
    const userRole = await prisma.role.findUnique({ where: { name: "user" } });
    if (!userRole) {
      return reply.code(500).send({ error: "Server misconfiguration" });
    }
    const passwordHash = await hashPassword(password);
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        userRoles: { create: { roleId: userRole.id } },
      },
    });
    await writeAudit(request, {
      actorUserId: user.id,
      action: "user_register",
      resourceType: "User",
      resourceId: user.id,
      metadata: { email: user.email },
    });
    return reply.code(201).send({ id: user.id, email: user.email });
  });

  app.post("/login", async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid input", details: parsed.error.flatten() });
    }
    const { email, password } = parsed.data;
    const throttleKey = `${request.ip}:${email.toLowerCase()}`;
    if (!loginThrottleAllow(throttleKey, 12, 15 * 60 * 1000)) {
      await writeAudit(request, {
        actorUserId: null,
        action: "login_rate_limited",
        metadata: { email },
      });
      return reply.code(429).send({ error: "Too many attempts" });
    }

    const user = await prisma.user.findUnique({
      where: { email },
      include: { userRoles: { include: { role: true } } },
    });
    const ok = user
      ? await verifyPassword(password, user.passwordHash)
      : await dummyVerify().then(() => false);
    if (!user || !ok) {
      await writeAudit(request, {
        actorUserId: null,
        action: "login_failure",
        metadata: { email },
      });
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    await prisma.session.deleteMany({ where: { userId: user.id } });

    const token = newSessionToken();
    const tokenHash = hashSessionToken(token);
    const expiresAt = new Date(Date.now() + SESSION_MS);
    await prisma.session.create({
      data: { token: tokenHash, userId: user.id, expiresAt },
    });

    setSessionCookie(reply, token, SESSION_MAX_AGE_SEC, opts.secureCookie);

    await writeAudit(request, {
      actorUserId: user.id,
      action: "login_success",
      resourceType: "User",
      resourceId: user.id,
      metadata: { email: user.email },
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        roles: user.userRoles.map((ur) => ur.role.name),
      },
    };
  });

  app.post(
    "/logout",
    { preHandler: requireAuth() },
    async (request, reply) => {
      const token = (request as unknown as { _sessionToken?: string })._sessionToken;
      if (token) {
        const tokenHash = hashSessionToken(token);
        await prisma.session.deleteMany({ where: { token: tokenHash } });
      }
      clearSessionCookie(reply);
      await writeAudit(request, {
        actorUserId: request.sessionUser!.id,
        action: "logout",
        resourceType: "User",
        resourceId: request.sessionUser!.id,
      });
      return { ok: true };
    },
  );

  app.get("/me", { preHandler: requireAuth() }, async (request) => {
    const u = request.sessionUser!;
    return {
      id: u.id,
      email: u.email,
      roles: u.roles.map((r) => r.name),
    };
  });

  app.patch(
    "/password",
    { preHandler: requireAuth() },
    async (request, reply) => {
      const parsed = changePasswordSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "Invalid input", details: parsed.error.flatten() });
      }
      const { currentPassword, newPassword } = parsed.data;
      const full = await prisma.user.findUniqueOrThrow({
        where: { id: request.sessionUser!.id },
      });
      const match = await verifyPassword(currentPassword, full.passwordHash);
      if (!match) {
        await writeAudit(request, {
          actorUserId: request.sessionUser!.id,
          action: "password_change_failure",
          resourceType: "User",
          resourceId: full.id,
        });
        return reply.code(401).send({ error: "Current password incorrect" });
      }
      await prisma.user.update({
        where: { id: full.id },
        data: { passwordHash: await hashPassword(newPassword) },
      });
      await prisma.session.deleteMany({ where: { userId: full.id } });
      clearSessionCookie(reply);
      await writeAudit(request, {
        actorUserId: full.id,
        action: "password_change_success",
        resourceType: "User",
        resourceId: full.id,
      });
      return { ok: true, message: "Password updated; please log in again." };
    },
  );
};

export default authRoutes;
