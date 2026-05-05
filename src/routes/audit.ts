import type { FastifyPluginAsync } from "fastify";
import { prisma } from "../prisma.js";
import { requireAnyRole } from "../auth/guards.js";
import { writeAudit } from "../lib/audit.js";

const auditRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", requireAnyRole("admin", "auditor_readonly"));

  app.get("/events", async (request) => {
    const q = request.query as { limit?: string };
    const limit = Math.min(200, Math.max(1, parseInt(q.limit ?? "50", 10) || 50));
    const events = await prisma.auditEvent.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
      select: {
        id: true,
        actorUserId: true,
        action: true,
        resourceType: true,
        resourceId: true,
        ip: true,
        userAgent: true,
        metadata: true,
        createdAt: true,
      },
    });
    await writeAudit(request, {
      actorUserId: request.sessionUser!.id,
      action: "audit_log_read",
      metadata: { limit },
    });
    return { events };
  });
};

export default auditRoutes;
