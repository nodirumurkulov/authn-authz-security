import type { preHandlerHookHandler } from "fastify";
import { CSRF_HEADER, verifyCsrfToken } from "../lib/csrf.js";
import { AuthorizationError, ErrorCode } from "../errors/index.js";

const STATE_CHANGING_METHODS = new Set(["POST", "PATCH", "PUT", "DELETE"]);

/**
 * Fastify preHandler hook that enforces CSRF token validation on
 * state-changing HTTP methods (POST, PATCH, PUT, DELETE).
 *
 * The client must send the token in the `x-csrf-token` header.
 * The expected token is read from the session (set during login).
 */
export function requireCsrf(): preHandlerHookHandler {
  return async (request) => {
    if (!STATE_CHANGING_METHODS.has(request.method)) return;

    if (!request.sessionUser) return;

    const expected = (request as unknown as { _csrfToken?: string })._csrfToken;
    if (!expected) {
      throw new AuthorizationError("CSRF token missing from session", ErrorCode.CSRF_SESSION_MISSING);
    }

    const received = request.headers[CSRF_HEADER];
    if (!received || typeof received !== "string") {
      throw new AuthorizationError("Missing CSRF token header", ErrorCode.CSRF_TOKEN_MISSING);
    }

    if (!verifyCsrfToken(expected, received)) {
      throw new AuthorizationError("Invalid CSRF token", ErrorCode.CSRF_TOKEN_INVALID);
    }
  };
}
