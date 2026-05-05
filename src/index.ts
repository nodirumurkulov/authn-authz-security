import Fastify from "fastify";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { loadConfig } from "./config.js";
import sessionPlugin from "./auth/sessionPlugin.js";
import healthRoutes from "./routes/health.js";
import authRoutes from "./routes/auth.js";
import documentRoutes from "./routes/documents.js";
import auditRoutes from "./routes/audit.js";
import adminRoutes from "./routes/admin.js";

const config = loadConfig();

const app = Fastify({
  logger: true,
  trustProxy: true,
  bodyLimit: 512 * 1024,
});

await app.register(helmet, {
  contentSecurityPolicy: false,
});

await app.register(cors, {
  origin: config.CORS_ORIGINS.length > 0 ? config.CORS_ORIGINS : false,
  credentials: true,
});

await app.register(rateLimit, {
  max: 300,
  timeWindow: "1 minute",
});

await app.register(sessionPlugin, { secret: config.SESSION_SECRET });

await app.register(healthRoutes);

await app.register(
  async (scope) => {
    await scope.register(rateLimit, {
      max: 60,
      timeWindow: "1 minute",
    });
    await scope.register(authRoutes, {
      secureCookie: config.NODE_ENV === "production",
    });
  },
  { prefix: "/auth" },
);
await app.register(documentRoutes, { prefix: "/api/documents" });
await app.register(auditRoutes, { prefix: "/api/audit" });
await app.register(adminRoutes, { prefix: "/api/admin" });

const address = await app.listen({ port: config.PORT, host: "0.0.0.0" });
app.log.info(`Listening on ${address}`);
