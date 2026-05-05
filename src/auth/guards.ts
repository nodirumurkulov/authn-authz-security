import type { preHandlerHookHandler } from "fastify";

export function requireAuth(): preHandlerHookHandler {
  return async (request, reply) => {
    if (!request.sessionUser) {
      return reply.code(401).send({ error: "Unauthorized" });
    }
  };
}

export function requireAnyRole(...allowed: string[]): preHandlerHookHandler {
  return async (request, reply) => {
    if (!request.sessionUser) {
      return reply.code(401).send({ error: "Unauthorized" });
    }
    const names = new Set(request.sessionUser.roles.map((r) => r.name));
    const ok = allowed.some((a) => names.has(a));
    if (!ok) {
      return reply.code(403).send({ error: "Forbidden" });
    }
  };
}

export function hasRole(user: { roles: { name: string }[] }, role: string): boolean {
  return user.roles.some((r) => r.name === role);
}
