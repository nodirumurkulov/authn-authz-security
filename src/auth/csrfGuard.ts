import type { preHandlerHookHandler } from "fastify";
import { CSRF_HEADER, verifyCsrfToken } from "../lib/csrf.js";

const STATE_CHANGING_METHODS = new Set(["POST", "PATCH", "PUT", "DELETE"]);

/**
 * Fastify preHandler hook that enforces CSRF token validation on
 * state-changing HTTP methods (POST, PATCH, PUT, DELETE).
 *
 * The client must send the token in the `x-csrf-token` header.
 * The expected token is read from the session (set during login).
 */
export function requireCsrf(): preHandlerHookHandler {
  return async (request, reply) => {
    if (!STATE_CHANGING_METHODS.has(request.method)) return;

    if (!request.sessionUser) return;

    const expected = (request as unknown as { _csrfToken?: string })._csrfToken;
    if (!expected) {
      return reply.code(403).send({ error: "CSRF token missing from session" });
    }

    const received = request.headers[CSRF_HEADER];
    if (!received || typeof received !== "string") {
      return reply.code(403).send({ error: "Missing CSRF token header" });
    }

    if (!verifyCsrfToken(expected, received)) {
      return reply.code(403).send({ error: "Invalid CSRF token" });
    }
  };
}
