const { PrismaClient } = require("@prisma/client");
const argon2 = require("argon2");
require("dotenv/config");

const prisma = new PrismaClient();

function resolveSeedPassword(envName) {
  const envValue = process.env[envName];
  if (envValue && envValue.length >= 10) {
    return envValue;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error(`${envName} is required in production and must be at least 10 characters.`);
  }
  return null;
}

async function main() {
  const roles = ["admin", "user", "auditor_readonly"];
  for (const name of roles) {
    await prisma.role.upsert({
      where: { name },
      create: { name },
      update: {},
    });
  }

  const adminRole = await prisma.role.findUniqueOrThrow({ where: { name: "admin" } });
  const userRole = await prisma.role.findUniqueOrThrow({ where: { name: "user" } });
  const auditorRole = await prisma.role.findUniqueOrThrow({
    where: { name: "auditor_readonly" },
  });

  const users = [
    {
      email: "admin@example.com",
      password: resolveSeedPassword("SEED_ADMIN_PASSWORD"),
      roleIds: [adminRole.id, userRole.id],
    },
    {
      email: "user@example.com",
      password: resolveSeedPassword("SEED_USER_PASSWORD"),
      roleIds: [userRole.id],
    },
    {
      email: "auditor@example.com",
      password: resolveSeedPassword("SEED_AUDITOR_PASSWORD"),
      roleIds: [auditorRole.id],
    },
  ];

  for (const u of users) {
    if (!u.password) {
      console.warn(
        `[seed warning] Missing password env var for ${u.email}. User updated but password unchanged.`,
      );
      continue;
    }
    const hash = await argon2.hash(u.password);
    const user = await prisma.user.upsert({
      where: { email: u.email },
      create: { email: u.email, passwordHash: hash },
      update: { passwordHash: hash },
    });
    await prisma.userRole.deleteMany({ where: { userId: user.id } });
    for (const roleId of u.roleIds) {
      await prisma.userRole.create({ data: { userId: user.id, roleId } });
    }
  }

  const demoUser = await prisma.user.findUniqueOrThrow({
    where: { email: "user@example.com" },
  });
  await prisma.document.deleteMany({ where: { userId: demoUser.id } });
  await prisma.document.create({
    data: {
      userId: demoUser.id,
      title: "Demo note",
      body: "Owned by user@example.com — try IDOR as another user.",
    },
  });
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
