import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import cookie from "@fastify/cookie";
import { prisma } from "../prisma.js";
import type { SessionUser } from "../types/fastify.js";
import { hashSessionToken } from "../lib/sessionToken.js";

const COOKIE_NAME = "sid";

export const SESSION_COOKIE = COOKIE_NAME;

const sessionPlugin: FastifyPluginAsync<{ secret: string }> = async (app, opts) => {
  await app.register(cookie, {
    secret: opts.secret,
    hook: "onRequest",
  });

  app.decorateRequest("sessionUser", null);

  app.addHook("onRequest", async (request) => {
    request.sessionUser = null;
    const raw = request.cookies[COOKIE_NAME];
    if (!raw) return;

    const unsigned = request.unsignCookie(raw);
    if (!unsigned.valid || !unsigned.value) return;

    const token = unsigned.value;
    const tokenHash = hashSessionToken(token);
    const session = await prisma.session.findUnique({
      where: { token: tokenHash },
      include: {
        user: {
          include: {
            userRoles: { include: { role: true } },
          },
        },
      },
    });

    if (!session || session.expiresAt < new Date()) {
      return;
    }

    const u = session.user;
    const sessionUser: SessionUser = {
      id: u.id,
      email: u.email,
      createdAt: u.createdAt,
      roles: u.userRoles.map((ur) => ({ name: ur.role.name })),
    };
    request.sessionUser = sessionUser;
    (request as unknown as { _sessionToken?: string })._sessionToken = token;
    (request as unknown as { _csrfToken?: string })._csrfToken = session.csrfToken;
  });
};

export default fp(sessionPlugin, { name: "session-cookie" });

export function setSessionCookie(
  reply: {
    setCookie: (
      name: string,
      value: string,
      options: Record<string, unknown>,
    ) => void;
  },
  token: string,
  maxAgeSec: number,
  secure: boolean,
): void {
  reply.setCookie(COOKIE_NAME, token, {
    path: "/",
    httpOnly: true,
    secure,
    sameSite: "lax",
    signed: true,
    maxAge: maxAgeSec,
  });
}

export function clearSessionCookie(reply: {
  clearCookie: (name: string, options: Record<string, unknown>) => void;
}): void {
  reply.clearCookie(COOKIE_NAME, { path: "/" });
}
