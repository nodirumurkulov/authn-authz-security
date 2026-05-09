import { randomBytes, timingSafeEqual } from "node:crypto";

const CSRF_TOKEN_BYTES = 32;

export const CSRF_HEADER = "x-csrf-token";

/** Generate a cryptographically random CSRF token. */
export function newCsrfToken(): string {
  return randomBytes(CSRF_TOKEN_BYTES).toString("base64url");
}

/** Constant-time comparison of two CSRF tokens. */
export function verifyCsrfToken(expected: string, received: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(received, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
