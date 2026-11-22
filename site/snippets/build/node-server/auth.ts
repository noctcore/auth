import { createAuth, pwnedPasswords, type Logger, type Mailer } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import { Redis } from 'ioredis';
import { config } from './config';
import { prisma } from './db';

// The longest a session can live. The Redis store must guard at least this
// long, so the same value goes to both.
const REMEMBER_ME_TTL = '30d';

// Bounded, so an outage fails requests in milliseconds, not after about 73 s.
export const redis = new Redis(config.redisUrl, {
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
  connectTimeout: 2_000,
  commandTimeout: 1_000,
  retryStrategy: (attempt) => Math.min(attempt * 200, 2_000),
});

redis.on('error', (error) => process.stderr.write(`redis: ${error.name}\n`));

const { sessions, counters } = redisStores(redis, {
  prefix: 'auth:',
  maxSessionTtl: REMEMBER_ME_TTL,
});

export const stores = {
  ...prismaStores({ delegate: prisma.user, tokenDelegate: prisma.authToken }),
  sessions,
  counters,
};

// What the package cannot return goes here: a breach check that failed, an
// audit sink or mailer that threw. Never secrets; user ids at most.
const logger: Logger = {
  warn: (message, context) =>
    process.stderr.write(`${JSON.stringify({ level: 'warn', message, ...context })}\n`),
  error: (message, context) =>
    process.stderr.write(`${JSON.stringify({ level: 'error', message, ...context })}\n`),
};

export function buildAuth(mailer: Mailer) {
  return createAuth({
    stores,
    password: { hasher: argon2id(), breachCheck: pwnedPasswords() },
    session: {
      rememberMeTtl: REMEMBER_ME_TTL,
      cookie: { secure: config.secureCookies },
    },
    secret: config.authSecret,
    urls: {
      resetPassword: (token) => `${config.origin}/reset-password#${token}`,
      // The link the old address gets after an email change, to undo it.
      revertEmailChange: (token) => `${config.origin}/email/revert#${token}`,
    },
    mailer,
    logger,
  });
}

export type AppAuth = ReturnType<typeof buildAuth>;
