import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { prisma } from "../prisma.js";
import { requireAnyRole } from "../auth/guards.js";
import { writeAudit } from "../lib/audit.js";
import { invalidateUserSessions } from "../lib/sessionRotation.js";

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
      return reply.code(400).send({ error: "Invalid parameters" });
    }
    const { userId } = paramsParsed.data;
    const parsed = assignRoleSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid input", details: parsed.error.flatten() });
    }
    const { roleName } = parsed.data;
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) {
      return reply.code(404).send({ error: "Not found" });
    }
    const role = await prisma.role.findUnique({ where: { name: roleName } });
    if (!role) {
      return reply.code(500).send({ error: "Server misconfiguration" });
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
      metadata: { roleName, targetEmail: target.email, sessionsInvalidated: invalidated },
    });
    return { ok: true, sessionsInvalidated: invalidated };
  });

  app.delete("/users/:userId/roles", async (request, reply) => {
    const paramsParsed = userIdParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      return reply.code(400).send({ error: "Invalid parameters" });
    }
    const { userId } = paramsParsed.data;
    const parsed = assignRoleSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid input", details: parsed.error.flatten() });
    }
    const { roleName } = parsed.data;
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) {
      return reply.code(404).send({ error: "Not found" });
    }
    const role = await prisma.role.findUnique({ where: { name: roleName } });
    if (!role) {
      return reply.code(500).send({ error: "Server misconfiguration" });
    }
    const existing = await prisma.userRole.findUnique({
      where: { userId_roleId: { userId, roleId: role.id } },
    });
    if (!existing) {
      return reply.code(404).send({ error: "User does not have this role" });
    }
    await prisma.userRole.delete({
      where: { userId_roleId: { userId, roleId: role.id } },
    });
    await writeAudit(request, {
      actorUserId: request.sessionUser!.id,
      action: "role_revoked",
      resourceType: "User",
      resourceId: userId,
      metadata: { roleName, targetEmail: target.email },
    });
    return { ok: true };
  });

  app.post("/users/:userId/unlock", async (request, reply) => {
    const paramsParsed = userIdParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      return reply.code(400).send({ error: "Invalid parameters" });
    }
    const { userId } = paramsParsed.data;
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) {
      return reply.code(404).send({ error: "Not found" });
    }
    if (target.failedLoginAttempts === 0 && !target.lockedUntil) {
      return reply.code(400).send({ error: "Account is not locked" });
    }
    await prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });
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
    return { ok: true, message: `Account ${target.email} unlocked` };
  });
};

export default adminRoutes;
