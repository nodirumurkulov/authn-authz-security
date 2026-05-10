import { beforeAll, afterAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { PrismaClient } from "@prisma/client";

const DATABASE_URL = "file:./test.db";

let app: FastifyInstance;
let prisma: PrismaClient;
let userDocumentId: string;
let targetUserId: string;
let hashPassword: (plain: string) => Promise<string>;

async function login(
  email: string,
  password: string,
): Promise<{ cookie: string; csrfToken: string }> {
  const res = await app.inject({
    method: "POST",
    url: "/auth/login",
    payload: { email, password },
  });
  expect(res.statusCode).toBe(200);
  const cookie = res.cookies.find((c) => c.name === "sid")?.value;
  expect(cookie).toBeTruthy();
  const body = res.json();
  return { cookie: `sid=${cookie}`, csrfToken: body.csrfToken };
}

beforeAll(async () => {
  process.env.DATABASE_URL = DATABASE_URL;
  process.env.NODE_ENV = "test";
  process.env.SESSION_SECRET = "test-session-secret-01234567890123456789";
  process.env.CORS_ORIGINS = "";

  const appModule = await import("../src/app.js");
  const passwordModule = await import("../src/lib/password.js");
  hashPassword = passwordModule.hashPassword;

  prisma = new PrismaClient();
  await prisma.auditEvent.deleteMany();
  await prisma.session.deleteMany();
  await prisma.document.deleteMany();
  await prisma.userRole.deleteMany();
  await prisma.user.deleteMany();
  await prisma.role.deleteMany();

  const [adminRole, userRole, auditorRole] = await Promise.all([
    prisma.role.create({ data: { name: "admin" } }),
    prisma.role.create({ data: { name: "user" } }),
    prisma.role.create({ data: { name: "auditor_readonly" } }),
  ]);

  const adminUser = await prisma.user.create({
    data: {
      email: "admin@example.com",
      passwordHash: await hashPassword("AdminPass1!x"),
    },
  });
  const user = await prisma.user.create({
    data: {
      email: "user@example.com",
      passwordHash: await hashPassword("UserPass1!x"),
    },
  });
  const secondUser = await prisma.user.create({
    data: {
      email: "other@example.com",
      passwordHash: await hashPassword("OtherPass1!x"),
    },
  });
  targetUserId = secondUser.id;

  await prisma.userRole.createMany({
    data: [
      { userId: adminUser.id, roleId: adminRole.id },
      { userId: adminUser.id, roleId: userRole.id },
      { userId: user.id, roleId: userRole.id },
      { userId: secondUser.id, roleId: userRole.id },
      { userId: secondUser.id, roleId: auditorRole.id },
    ],
  });

  const userDoc = await prisma.document.create({
    data: {
      userId: user.id,
      title: "User private doc",
      body: "Should not be accessible by other normal users.",
    },
  });
  userDocumentId = userDoc.id;

  app = await appModule.buildApp({
    DATABASE_URL,
    SESSION_SECRET: "test-session-secret-01234567890123456789",
    NODE_ENV: "test",
    PORT: 0,
    CORS_ORIGINS: [],
  });
});

afterAll(async () => {
  await app.close();
  await prisma.$disconnect();
});

describe("Auth/session security", () => {
  it("logs in and returns session-bound user profile", async () => {
    const { cookie } = await login("user@example.com", "UserPass1!x");

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { cookie },
    });
    expect(me.statusCode).toBe(200);
    const body = me.json();
    expect(body).toMatchObject({
      email: "user@example.com",
      roles: ["user"],
    });
    expect(body.sessionRotatedAt).toBeNull();
  });

  it("rejects invalid credentials", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "user@example.com", password: "WrongPassword" },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe("Authorization boundaries", () => {
  it("blocks IDOR: normal user cannot read someone else's document", async () => {
    const { cookie } = await login("other@example.com", "OtherPass1!x");
    const res = await app.inject({
      method: "GET",
      url: `/api/documents/${userDocumentId}`,
      headers: { cookie },
    });
    expect(res.statusCode).toBe(403);
  });

  it("allows admin to read any document", async () => {
    const { cookie } = await login("admin@example.com", "AdminPass1!x");
    const res = await app.inject({
      method: "GET",
      url: `/api/documents/${userDocumentId}`,
      headers: { cookie },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      id: userDocumentId,
      title: "User private doc",
    });
  });
});

describe("CSRF protection", () => {
  it("returns csrfToken in login response", async () => {
    const { csrfToken } = await login("user@example.com", "UserPass1!x");
    expect(csrfToken).toBeTruthy();
    expect(typeof csrfToken).toBe("string");
    expect(csrfToken.length).toBeGreaterThan(20);
  });

  it("allows GET /auth/csrf-token to retrieve the token", async () => {
    const { cookie, csrfToken } = await login("user@example.com", "UserPass1!x");
    const res = await app.inject({
      method: "GET",
      url: "/auth/csrf-token",
      headers: { cookie },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().csrfToken).toBe(csrfToken);
  });

  it("rejects POST without CSRF token header", async () => {
    const { cookie } = await login("user@example.com", "UserPass1!x");
    const res = await app.inject({
      method: "POST",
      url: "/api/documents",
      headers: { cookie },
      payload: { title: "test doc" },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toMatch(/CSRF/i);
  });

  it("rejects POST with wrong CSRF token", async () => {
    const { cookie } = await login("user@example.com", "UserPass1!x");
    const res = await app.inject({
      method: "POST",
      url: "/api/documents",
      headers: { cookie, "x-csrf-token": "wrong-token-value" },
      payload: { title: "test doc" },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toMatch(/CSRF/i);
  });

  it("allows POST with valid CSRF token", async () => {
    const { cookie, csrfToken } = await login("user@example.com", "UserPass1!x");
    const res = await app.inject({
      method: "POST",
      url: "/api/documents",
      headers: { cookie, "x-csrf-token": csrfToken },
      payload: { title: "CSRF-protected doc" },
    });
    expect(res.statusCode).toBe(201);
    expect(res.json().title).toBe("CSRF-protected doc");
  });
});

describe("Session rotation on password change", () => {
  it("rotates session and returns new CSRF token on password change", async () => {
    const reg = await app.inject({
      method: "POST",
      url: "/auth/register",
      payload: { email: "rotate-test@example.com", password: "OldPassword1!x" },
    });
    expect(reg.statusCode).toBe(201);

    const { cookie, csrfToken } = await login("rotate-test@example.com", "OldPassword1!x");

    const changeRes = await app.inject({
      method: "PATCH",
      url: "/auth/password",
      headers: { cookie, "x-csrf-token": csrfToken },
      payload: { currentPassword: "OldPassword1!x", newPassword: "NewPassword1!x" },
    });
    expect(changeRes.statusCode).toBe(200);
    const body = changeRes.json();
    expect(body.ok).toBe(true);
    expect(body.csrfToken).toBeTruthy();
    expect(body.csrfToken).not.toBe(csrfToken);

    const newCookie = changeRes.cookies.find((c) => c.name === "sid")?.value;
    expect(newCookie).toBeTruthy();

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { cookie: `sid=${newCookie}` },
    });
    expect(me.statusCode).toBe(200);
    const meBody = me.json();
    expect(meBody.email).toBe("rotate-test@example.com");
    expect(meBody.sessionRotatedAt).toBeTruthy();
  });

  it("old session is invalid after password change rotation", async () => {
    const { cookie, csrfToken } = await login("rotate-test@example.com", "NewPassword1!x");

    await app.inject({
      method: "PATCH",
      url: "/auth/password",
      headers: { cookie, "x-csrf-token": csrfToken },
      payload: { currentPassword: "NewPassword1!x", newPassword: "FinalPassword1!x" },
    });

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { cookie },
    });
    expect(me.statusCode).toBe(401);
  });
});

describe("Session invalidation on privilege change", () => {
  it("invalidates target user session when admin assigns a role", async () => {
    const targetSession = await login("other@example.com", "OtherPass1!x");
    const adminSession = await login("admin@example.com", "AdminPass1!x");

    const assignRes = await app.inject({
      method: "POST",
      url: `/api/admin/users/${targetUserId}/roles`,
      headers: { cookie: adminSession.cookie, "x-csrf-token": adminSession.csrfToken },
      payload: { roleName: "admin" },
    });
    expect(assignRes.statusCode).toBe(200);
    expect(assignRes.json().sessionsInvalidated).toBeGreaterThanOrEqual(1);

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { cookie: targetSession.cookie },
    });
    expect(me.statusCode).toBe(401);
  });

  it("invalidates target user session when admin revokes a role", async () => {
    const targetSession = await login("other@example.com", "OtherPass1!x");
    const adminSession = await login("admin@example.com", "AdminPass1!x");

    const revokeRes = await app.inject({
      method: "DELETE",
      url: `/api/admin/users/${targetUserId}/roles`,
      headers: { cookie: adminSession.cookie, "x-csrf-token": adminSession.csrfToken },
      payload: { roleName: "admin" },
    });
    expect(revokeRes.statusCode).toBe(200);
    expect(revokeRes.json().sessionsInvalidated).toBeGreaterThanOrEqual(1);

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { cookie: targetSession.cookie },
    });
    expect(me.statusCode).toBe(401);
  });

  it("admin session remains valid after modifying another user", async () => {
    const adminSession = await login("admin@example.com", "AdminPass1!x");

    await app.inject({
      method: "POST",
      url: `/api/admin/users/${targetUserId}/roles`,
      headers: { cookie: adminSession.cookie, "x-csrf-token": adminSession.csrfToken },
      payload: { roleName: "auditor_readonly" },
    });

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { cookie: adminSession.cookie },
    });
    expect(me.statusCode).toBe(200);
    expect(me.json().email).toBe("admin@example.com");
  });
});
