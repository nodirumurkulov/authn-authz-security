import argon2 from "argon2";

export async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, { type: argon2.argon2id });
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}

const DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dummyhashvaluefortimingequalisation";

/** Run a dummy hash comparison so response time is constant whether user exists or not. */
export async function dummyVerify(): Promise<void> {
  await argon2.verify(DUMMY_HASH, "dummy-password").catch(() => {});
}
