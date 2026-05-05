import { randomBytes, createHash } from "node:crypto";

/** Opaque session token (sent to client in httpOnly cookie). */
export function newSessionToken(): string {
  return randomBytes(32).toString("base64url");
}

/** One-way SHA-256 hash of the token for DB storage. */
export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
