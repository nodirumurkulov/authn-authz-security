import type { FastifyInstance } from "fastify";
import { AppError } from "./AppError.js";
import { serializeError } from "./errorSerializer.js";
import { logError } from "./errorLogger.js";

/**
 * Register a global error handler on the Fastify instance.
 * - AppError subclasses are serialized with their code and status.
 * - Fastify validation errors (from schema/content-type) are wrapped.
 * - Unknown errors return a generic 500 without leaking internals.
 */
export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((error: Error, request, reply) => {
    const requestId = (request as unknown as { _requestId?: string })._requestId;

    if (error instanceof AppError) {
      if (error.statusCode >= 500) {
        logError(app.log, error, requestId);
      }
      const { statusCode, body } = serializeError(error, requestId);
      return reply.code(statusCode).send(body);
    }

    const fastifyError = error as Error & { statusCode?: number; code?: string };
    if (fastifyError.statusCode && fastifyError.statusCode < 500) {
      return reply.code(fastifyError.statusCode).send({
        error: {
          code: fastifyError.code ?? "REQUEST_ERROR",
          message: fastifyError.message,
          ...(requestId ? { requestId } : {}),
        },
      });
    }

    logError(app.log, error, requestId);

    const { statusCode, body } = serializeError(error, requestId);
    return reply.code(statusCode).send(body);
  });
}
