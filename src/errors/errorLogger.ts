import type { FastifyBaseLogger } from "fastify";
import { AppError } from "./AppError.js";

const SENSITIVE_KEYS = new Set([
  "password",
  "currentPassword",
  "newPassword",
  "token",
  "csrfToken",
  "sessionSecret",
  "authorization",
  "cookie",
  "secret",
]);

function sanitizeValue(key: string, value: unknown): unknown {
  if (SENSITIVE_KEYS.has(key)) return "[REDACTED]";
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return sanitizeObject(value as Record<string, unknown>);
  }
  return value;
}

function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    sanitized[key] = sanitizeValue(key, value);
  }
  return sanitized;
}

export function logError(
  logger: FastifyBaseLogger,
  error: unknown,
  requestId?: string,
): void {
  if (error instanceof AppError) {
    const sanitizedDetails = error.details && typeof error.details === "object"
      ? sanitizeObject(error.details as Record<string, unknown>)
      : error.details;

    logger.warn({
      errorCode: error.code,
      statusCode: error.statusCode,
      message: error.message,
      details: sanitizedDetails,
      requestId,
    });
    return;
  }

  const err = error instanceof Error ? error : new Error(String(error));
  logger.error({
    err: {
      message: err.message,
      stack: err.stack,
    },
    requestId,
    msg: "Unhandled error",
  });
}
