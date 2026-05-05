import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { prisma } from "../prisma.js";
import { requireAnyRole } from "../auth/guards.js";
import { writeAudit } from "../lib/audit.js";

const assignRoleSchema = z.object({
  roleName: z.enum(["admin", "user", "auditor_readonly"]),
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
        userRoles: { select: { role: { select: { name: true } } } },
      },
    });
    return {
      users: users.map((u) => ({
        id: u.id,
        email: u.email,
        createdAt: u.createdAt,
        roles: u.userRoles.map((ur) => ur.role.name),
      })),
    };
  });

  app.post("/users/:userId/roles", async (request, reply) => {
    const { userId } = request.params as { userId: string };
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
    await writeAudit(request, {
      actorUserId: request.sessionUser!.id,
      action: "role_assigned",
      resourceType: "User",
      resourceId: userId,
      metadata: { roleName, targetEmail: target.email },
    });
    return { ok: true };
  });
};

export default adminRoutes;
