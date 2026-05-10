import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";

export function generateRequestId(): string {
  return randomBytes(16).toString("hex");
}

/**
 * Register an onRequest hook that assigns a unique request ID and
 * an onSend hook that echoes it back as X-Request-Id.
 */
export function registerRequestId(app: FastifyInstance): void {
  app.addHook("onRequest", async (request) => {
    const incoming = request.headers["x-request-id"];
    const id =
      typeof incoming === "string" && incoming.length > 0
        ? incoming
        : generateRequestId();
    (request as unknown as { _requestId: string })._requestId = id;
  });

  app.addHook("onSend", async (_request, reply) => {
    const id = (_request as unknown as { _requestId?: string })._requestId;
    if (id) {
      void reply.header("x-request-id", id);
    }
  });
}
