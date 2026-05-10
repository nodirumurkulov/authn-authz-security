import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { prisma } from "../prisma.js";
import { requireAuth, hasRole } from "../auth/guards.js";
import { writeAudit } from "../lib/audit.js";
import {
  ValidationError,
  NotFoundError,
  AuthorizationError,
} from "../errors/index.js";

const createDocSchema = z.object({
  title: z.string().min(1).max(200),
  body: z.string().max(50_000).default(""),
});

const updateDocSchema = z.object({
  title: z.string().min(1).max(200).optional(),
  body: z.string().max(50_000).optional(),
});

const idParamSchema = z.object({
  id: z.string().min(1).max(100),
});

const documentRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", requireAuth());

  app.get("/", async (request) => {
    const u = request.sessionUser!;
    const where = hasRole(u, "admin") ? {} : { userId: u.id };
    const docs = await prisma.document.findMany({
      where,
      orderBy: { updatedAt: "desc" },
      select: { id: true, title: true, userId: true, createdAt: true, updatedAt: true },
    });
    return { documents: docs };
  });

  app.post("/", async (request, reply) => {
    const parsed = createDocSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new ValidationError("Invalid input", parsed.error.flatten());
    }
    const { title, body } = parsed.data;
    const doc = await prisma.document.create({
      data: { userId: request.sessionUser!.id, title, body },
    });
    await writeAudit(request, {
      actorUserId: request.sessionUser!.id,
      action: "document_create",
      resourceType: "Document",
      resourceId: doc.id,
      metadata: { title },
    });
    return reply.code(201).send(doc);
  });

  app.get("/:id", async (request, reply) => {
    const paramsParsed = idParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      throw new ValidationError("Invalid parameters", paramsParsed.error.flatten());
    }
    const { id } = paramsParsed.data;
    const doc = await prisma.document.findUnique({ where: { id } });
    if (!doc) {
      throw new NotFoundError("Document");
    }
    const u = request.sessionUser!;
    if (!hasRole(u, "admin") && doc.userId !== u.id) {
      throw new AuthorizationError();
    }
    return doc;
  });

  app.patch("/:id", async (request, reply) => {
    const paramsParsed = idParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      throw new ValidationError("Invalid parameters", paramsParsed.error.flatten());
    }
    const { id } = paramsParsed.data;
    const parsed = updateDocSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new ValidationError("Invalid input", parsed.error.flatten());
    }
    const doc = await prisma.document.findUnique({ where: { id } });
    if (!doc) {
      throw new NotFoundError("Document");
    }
    const u = request.sessionUser!;
    if (!hasRole(u, "admin") && doc.userId !== u.id) {
      throw new AuthorizationError();
    }
    const data = parsed.data;
    const updated = await prisma.document.update({
      where: { id },
      data: {
        ...(data.title !== undefined ? { title: data.title } : {}),
        ...(data.body !== undefined ? { body: data.body } : {}),
      },
    });
    await writeAudit(request, {
      actorUserId: u.id,
      action: "document_update",
      resourceType: "Document",
      resourceId: id,
    });
    return updated;
  });

  app.delete("/:id", async (request, reply) => {
    const paramsParsed = idParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      throw new ValidationError("Invalid parameters", paramsParsed.error.flatten());
    }
    const { id } = paramsParsed.data;
    const doc = await prisma.document.findUnique({ where: { id } });
    if (!doc) {
      throw new NotFoundError("Document");
    }
    const u = request.sessionUser!;
    if (!hasRole(u, "admin") && doc.userId !== u.id) {
      throw new AuthorizationError();
    }
    await prisma.document.delete({ where: { id } });
    await writeAudit(request, {
      actorUserId: u.id,
      action: "document_delete",
      resourceType: "Document",
      resourceId: id,
    });
    return reply.code(204).send();
  });
};

export default documentRoutes;
