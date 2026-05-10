import type { preHandlerHookHandler } from "fastify";
import { AuthenticationError, AuthorizationError, ErrorCode } from "../errors/index.js";

export function requireAuth(): preHandlerHookHandler {
  return async (request) => {
    if (!request.sessionUser) {
      throw new AuthenticationError("Unauthorized", ErrorCode.UNAUTHORIZED);
    }
  };
}

export function requireAnyRole(...allowed: string[]): preHandlerHookHandler {
  return async (request) => {
    if (!request.sessionUser) {
      throw new AuthenticationError("Unauthorized", ErrorCode.UNAUTHORIZED);
    }
    const names = new Set(request.sessionUser.roles.map((r) => r.name));
    const ok = allowed.some((a) => names.has(a));
    if (!ok) {
      throw new AuthorizationError("Insufficient role", ErrorCode.INSUFFICIENT_ROLE);
    }
  };
}

export function hasRole(user: { roles: { name: string }[] }, role: string): boolean {
  return user.roles.some((r) => r.name === role);
}
