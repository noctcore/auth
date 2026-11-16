// The landing page shows this file from the marker line down. The lines above
// it only declare what an app already has, so the sample compiles as shown.
import type { AuthErrorCode, Mailer, RequestMeta } from '@noctcore/auth';
import type { Redis } from 'ioredis';
import type { PrismaClient } from '../start/generated/prisma/client';

declare const prisma: PrismaClient;
declare const redis: Redis;
declare const mailer: Mailer;
declare function reply(status: number, body: unknown): Response;
declare function statusFor(code: AuthErrorCode): number;

// landing:start
import { createAuth, toPublicError } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';

const { users, tokens } = prismaStores({
  delegate: prisma.user,
  tokenDelegate: prisma.authToken,
});
const { sessions, counters } = redisStores(redis);

export const auth = createAuth({
  stores: { users, tokens, sessions, counters },
  password: { hasher: argon2id() },
  secret: process.env.AUTH_SECRET!,
  mailer,
});

// In your own route handler:
export async function login(email: string, password: string, meta: RequestMeta) {
  const result = await auth.login({ email, password, meta });

  if (!result.ok) {
    // A wrong password, an unknown address and a locked account
    // all answer invalid_credentials, after the same work.
    return reply(statusFor(result.code), toPublicError(result));
  }

  return reply(200, { signedIn: result.value.kind === 'session' });
}
