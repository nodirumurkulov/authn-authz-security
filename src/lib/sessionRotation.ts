import { prisma } from "../prisma.js";
import { newSessionToken, hashSessionToken } from "./sessionToken.js";
import { newCsrfToken } from "./csrf.js";

const SESSION_MS = 24 * 60 * 60 * 1000;

export interface RotationResult {
  token: string;
  csrfToken: string;
  expiresAt: Date;
}

/**
 * Rotate a user's session: delete all existing sessions and create a new one.
 * Returns the new raw token (for cookie) and CSRF token (for response body).
 */
export async function rotateUserSession(userId: string): Promise<RotationResult> {
  await prisma.session.deleteMany({ where: { userId } });

  const token = newSessionToken();
  const tokenHash = hashSessionToken(token);
  const csrfToken = newCsrfToken();
  const expiresAt = new Date(Date.now() + SESSION_MS);

  await prisma.session.create({
    data: {
      token: tokenHash,
      csrfToken,
      userId,
      expiresAt,
      rotatedAt: new Date(),
    },
  });

  return { token, csrfToken, expiresAt };
}

/**
 * Invalidate all sessions for a user without creating a new one.
 * Used when an admin changes another user's privileges — that user
 * must re-authenticate to pick up the new role set.
 */
export async function invalidateUserSessions(userId: string): Promise<number> {
  const result = await prisma.session.deleteMany({ where: { userId } });
  return result.count;
}
