import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { prisma } from "../prisma.js";
import { requireAnyRole } from "../auth/guards.js";
import { writeAudit } from "../lib/audit.js";
import { invalidateUserSessions } from "../lib/sessionRotation.js";
import {
  ValidationError,
  NotFoundError,
  ServerMisconfigurationError,
} from "../errors/index.js";

const assignRoleSchema = z.object({
  roleName: z.enum(["admin", "user", "auditor_readonly"]),
});

const userIdParamSchema = z.object({
  userId: z.string().min(1).max(100),
});

const adminRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", requireAnyRole("admin"));

  app.get("/users", async () => {
    const users = await prisma.user.findMany({
      orderBy: { email: "asc" },
      select: {
        id: true,
        email: true,
        createdAt: true,
        failedLoginAttempts: true,
        lockedUntil: true,
        userRoles: { select: { role: { select: { name: true } } } },
      },
    });
    return {
      users: users.map((u) => ({
        id: u.id,
        email: u.email,
        createdAt: u.createdAt,
        roles: u.userRoles.map((ur) => ur.role.name),
        failedLoginAttempts: u.failedLoginAttempts,
        locked: u.lockedUntil ? u.lockedUntil > new Date() : false,
        lockedUntil: u.lockedUntil,
      })),
    };
  });

  app.post("/users/:userId/roles", async (request, reply) => {
    const paramsParsed = userIdParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      throw new ValidationError("Invalid parameters", paramsParsed.error.flatten());
    }
    const { userId } = paramsParsed.data;
    const parsed = assignRoleSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new ValidationError("Invalid input", parsed.error.flatten());
    }
    const { roleName } = parsed.data;
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) {
      throw new NotFoundError("User");
    }
    const role = await prisma.role.findUnique({ where: { name: roleName } });
    if (!role) {
      throw new ServerMisconfigurationError();
    }
    await prisma.userRole.upsert({
      where: { userId_roleId: { userId, roleId: role.id } },
      create: { userId, roleId: role.id },
      update: {},
    });
    const invalidated = await invalidateUserSessions(userId);

    await writeAudit(request, {
      actorUserId: request.sessionUser!.id,
      action: "role_assigned",
      resourceType: "User",
      resourceId: userId,
      metadata: { roleName, targetEmail: target.email },
    });
    if (invalidated > 0) {
      await writeAudit(request, {
        actorUserId: request.sessionUser!.id,
        action: "sessions_invalidated",
        resourceType: "User",
        resourceId: userId,
        metadata: { reason: "role_assigned", count: invalidated, targetEmail: target.email },
      });
    }
    return { ok: true, sessionsInvalidated: invalidated };
  });

  app.delete("/users/:userId/roles", async (request, reply) => {
    const paramsParsed = userIdParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      throw new ValidationError("Invalid parameters", paramsParsed.error.flatten());
    }
    const { userId } = paramsParsed.data;
    const parsed = assignRoleSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new ValidationError("Invalid input", parsed.error.flatten());
    }
    const { roleName } = parsed.data;
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) {
      throw new NotFoundError("User");
    }
    const role = await prisma.role.findUnique({ where: { name: roleName } });
    if (!role) {
      throw new ServerMisconfigurationError();
    }
    const existing = await prisma.userRole.findUnique({
      where: { userId_roleId: { userId, roleId: role.id } },
    });
    if (!existing) {
      throw new NotFoundError("Role assignment");
    }
    await prisma.userRole.delete({
      where: { userId_roleId: { userId, roleId: role.id } },
    });
    const invalidated = await invalidateUserSessions(userId);

    await writeAudit(request, {
      actorUserId: request.sessionUser!.id,
      action: "role_revoked",
      resourceType: "User",
      resourceId: userId,
      metadata: { roleName, targetEmail: target.email },
    });
    if (invalidated > 0) {
      await writeAudit(request, {
        actorUserId: request.sessionUser!.id,
        action: "sessions_invalidated",
        resourceType: "User",
        resourceId: userId,
        metadata: { reason: "role_revoked", count: invalidated, targetEmail: target.email },
      });
    }
    return { ok: true, sessionsInvalidated: invalidated };
  });

  app.post("/users/:userId/unlock", async (request, reply) => {
    const paramsParsed = userIdParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      throw new ValidationError("Invalid parameters", paramsParsed.error.flatten());
    }
    const { userId } = paramsParsed.data;
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) {
      throw new NotFoundError("User");
    }
    if (target.failedLoginAttempts === 0 && !target.lockedUntil) {
      throw new ValidationError("Account is not locked");
    }
    await prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });
    const invalidated = await invalidateUserSessions(userId);

    await writeAudit(request, {
      actorUserId: request.sessionUser!.id,
      action: "account_unlocked",
      resourceType: "User",
      resourceId: userId,
      metadata: {
        targetEmail: target.email,
        previousFailedAttempts: target.failedLoginAttempts,
      },
    });
    if (invalidated > 0) {
      await writeAudit(request, {
        actorUserId: request.sessionUser!.id,
        action: "sessions_invalidated",
        resourceType: "User",
        resourceId: userId,
        metadata: { reason: "account_unlocked", count: invalidated, targetEmail: target.email },
      });
    }
    return { ok: true, message: `Account ${target.email} unlocked`, sessionsInvalidated: invalidated };
  });
};

export default adminRoutes;
