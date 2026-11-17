// The core, on Prisma for users and tokens and Redis for sessions and counters.
import { createAuth, type AuthUser, type Mailer } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import type { Redis } from 'ioredis';
import type { AppConfig } from './config';
import type { PrismaClient } from './generated/prisma/client';

export interface AppUser extends AuthUser {
  readonly role: string;
}

export function buildAuth(config: AppConfig, prisma: PrismaClient, redis: Redis, mailer: Mailer) {
  const { users, tokens } = prismaStores<AppUser>({
    delegate: prisma.user,
    tokenDelegate: prisma.authToken,
    select: { role: true },
    toUser: (row) => ({
      id: String(row['id']),
      email: String(row['email']),
      emailVerified: row['emailVerified'] === true,
      role: String(row['role']),
    }),
  });

  const { sessions, counters } = redisStores(redis, { prefix: config.redisPrefix });

  return createAuth({
    stores: { users, tokens, sessions, counters },
    password: { hasher: argon2id(), breachCheck: false },
    session: { cookie: { secure: config.secureCookies } },
    secret: config.authSecret,
    urls: { resetPassword: (token) => `${config.origin}/reset-password#${token}` },
    mailer,
  });
}

export type AppAuth = ReturnType<typeof buildAuth>;
