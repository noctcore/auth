import { createAuth, pwnedPasswords } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import { Redis } from 'ioredis';
import { prisma } from './db';

const secret = process.env.AUTH_SECRET;

if (!secret) throw new Error('Set AUTH_SECRET to 32 random bytes or more');

// Users and one-time tokens live in Postgres, sessions and counters in Redis.
const { users, tokens } = prismaStores({
  delegate: prisma.user,
  tokenDelegate: prisma.authToken,
});

const { sessions, counters } = redisStores(
  new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379'),
  { prefix: 'auth:' },
);

export const auth = createAuth({
  stores: { users, tokens, sessions, counters },
  password: { hasher: argon2id(), breachCheck: pwnedPasswords() },
  secret,
  // Password reset is a link by default, so the flow needs to know where it points.
  urls: { resetPassword: (token) => `https://app.example/reset-password#${token}` },
  // Mail events go to your own templates and queue. Printing them is enough to start.
  mailer: {
    async send(event) {
      process.stdout.write(`[mail] ${event.type} to ${event.to}\n`);
    },
  },
});
