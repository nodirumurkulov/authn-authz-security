import { randomBytes } from "node:crypto";

/** Opaque session token (stored in DB + httpOnly cookie). */
export function newSessionToken(): string {
  return randomBytes(32).toString("base64url");
}
