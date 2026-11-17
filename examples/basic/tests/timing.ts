// Wall-clock timing of sign-up on the real adapters: users and tokens in
// Postgres through Prisma, counters and sessions in Redis, Argon2id hashing.
//
// The in-memory benchmark (`bun run bench:timing`) makes a store call cost
// microseconds; here each one is a network round trip, so this is where a
// difference between the taken-address and the new-address path would show
// at the size it has in production. Attack A004 pins both store call
// sequences; this script reads the clock for a person, is not run in CI and
// never fails a build.
//
//   bun run services:up
//   bun run build
//   bun run bench:timing:stores                       100 samples per arm
//   bun run bench:timing:stores -- --samples 400 --seed 7
//
// Each run uses its own Redis prefix and address domain, and deletes what it
// created when it ends.
import { createAuth, type Door } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores } from '@noctcore/auth-prisma';
import { recordingMailer, uniqueId } from '@noctcore/auth/testing';
import { redisStores } from '@noctcore/auth-redis';
import { Redis } from 'ioredis';
import { compare, meta, summarize } from '../../../packages/auth/tests/timing/compare';
import { createPrisma } from '../src/db';

const PASSWORD = 'correct horse battery';
const UNLIMITED = { limit: 1_000_000_000, window: '15m' } as const;
const DOORS: Door[] = ['register'];

const databaseUrl = process.env['DATABASE_URL'] ?? 'postgresql://auth:auth@localhost:5440/auth';
const redisUrl = process.env['REDIS_URL'] ?? 'redis://localhost:6390';

const run = uniqueId('timing');
const domain = `${run}.example`;
const prefix = `${run}:`;
const known = `known@${domain}`;

const prisma = createPrisma(databaseUrl);
const redis = new Redis(redisUrl, { maxRetriesPerRequest: 1 });

const { users, tokens } = prismaStores({
  delegate: prisma.user,
  tokenDelegate: prisma.authToken,
});

const { sessions, counters } = redisStores(redis, { prefix });

const auth = createAuth({
  stores: { users, tokens, sessions, counters },
  password: { hasher: argon2id(), breachCheck: false },
  secret: 'timing-benchmark-secret-at-least-32-bytes',
  urls: { resetPassword: (token) => `https://app.example/reset#${token}` },
  throttle: { doors: Object.fromEntries(DOORS.map((door) => [door, UNLIMITED])) },
  mailer: recordingMailer(),
});

async function cleanUp(): Promise<void> {
  const created = await prisma.user.findMany({
    where: { email: { endsWith: `@${domain}` } },
    select: { id: true },
  });

  const ids = created.map((user) => user.id);

  await prisma.$transaction([
    prisma.authToken.deleteMany({ where: { userId: { in: ids } } }),
    prisma.user.deleteMany({ where: { id: { in: ids } } }),
  ]);

  const keys = await redis.keys(`${prefix}*`);

  if (keys.length > 0) await redis.del(...keys);
}

async function main(): Promise<void> {
  console.log('Sign-up timing on Postgres (Prisma) and Redis, Argon2id defaults.');

  await auth.register({ email: known, password: PASSWORD, meta: meta() });

  const results = [
    await compare({
      name: 'register on real stores: taken address vs new address',
      arms: [
        ['taken address', () => auth.register({ email: known, password: PASSWORD, meta: meta() })],
        [
          'new address',
          (i) => auth.register({ email: `new-${i}@${domain}`, password: PASSWORD, meta: meta() }),
        ],
      ],
    }),
  ];

  summarize(results);
}

try {
  await main();
} finally {
  await cleanUp();
  await prisma.$disconnect();
  await redis.quit();
}
