import { beforeAll, afterAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { PrismaClient } from "@prisma/client";

const DATABASE_URL = "file:./test.db";

let app: FastifyInstance;
let prisma: PrismaClient;
let userDocumentId: string;
let hashPassword: (plain: string) => Promise<string>;

async function login(email: string, password: string): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/auth/login",
    payload: { email, password },
  });
  expect(res.statusCode).toBe(200);
  const cookie = res.cookies.find((c) => c.name === "sid")?.value;
  expect(cookie).toBeTruthy();
  return `sid=${cookie}`;
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
    const sidCookie = await login("user@example.com", "UserPass1!x");

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: { cookie: sidCookie },
    });
    expect(me.statusCode).toBe(200);
    expect(me.json()).toMatchObject({
      email: "user@example.com",
      roles: ["user"],
    });
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
    const otherUserCookie = await login("other@example.com", "OtherPass1!x");
    const res = await app.inject({
      method: "GET",
      url: `/api/documents/${userDocumentId}`,
      headers: { cookie: otherUserCookie },
    });
    expect(res.statusCode).toBe(403);
  });

  it("allows admin to read any document", async () => {
    const adminCookie = await login("admin@example.com", "AdminPass1!x");
    const res = await app.inject({
      method: "GET",
      url: `/api/documents/${userDocumentId}`,
      headers: { cookie: adminCookie },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      id: userDocumentId,
      title: "User private doc",
    });
  });
});
