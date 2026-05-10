import type { FastifyRequest } from "fastify";
import { prisma } from "../prisma.js";

export async function writeAudit(
  req: FastifyRequest,
  params: {
    actorUserId: string | null;
    action: string;
    resourceType?: string | null;
    resourceId?: string | null;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  const ip = req.ip;
  const userAgent = req.headers["user-agent"] ?? null;
  const requestId = (req as unknown as { _requestId?: string })._requestId;
  const enrichedMetadata = {
    ...params.metadata,
    ...(requestId ? { requestId } : {}),
  };
  const hasMetadata = Object.keys(enrichedMetadata).length > 0;
  await prisma.auditEvent.create({
    data: {
      actorUserId: params.actorUserId,
      action: params.action,
      resourceType: params.resourceType ?? null,
      resourceId: params.resourceId ?? null,
      ip,
      userAgent: typeof userAgent === "string" ? userAgent : null,
      metadata: hasMetadata ? JSON.stringify(enrichedMetadata) : null,
    },
  });
}
