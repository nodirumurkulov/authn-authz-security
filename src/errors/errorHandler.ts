import type { FastifyInstance } from "fastify";
import { AppError } from "./AppError.js";
import { serializeError } from "./errorSerializer.js";

/**
 * Register a global error handler on the Fastify instance.
 * - AppError subclasses are serialized with their code and status.
 * - Fastify validation errors (from schema/content-type) are wrapped.
 * - Unknown errors return a generic 500 without leaking internals.
 */
export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((error, request, reply) => {
    const requestId = (request as unknown as { _requestId?: string })._requestId;

    if (error instanceof AppError) {
      const { statusCode, body } = serializeError(error, requestId);
      return reply.code(statusCode).send(body);
    }

    if (error.statusCode && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: {
          code: error.code ?? "REQUEST_ERROR",
          message: error.message,
          ...(requestId ? { requestId } : {}),
        },
      });
    }

    if (app.log && typeof app.log.error === "function") {
      app.log.error({
        err: error,
        requestId,
        msg: "Unhandled error",
      });
    }

    const { statusCode, body } = serializeError(error, requestId);
    return reply.code(statusCode).send(body);
  });
}
