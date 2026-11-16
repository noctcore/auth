import { Redis } from 'ioredis';
import { afterAll, describe, expect, it } from 'vitest';
import {
  counterStoreConformance,
  runConformance,
  sessionStoreConformance,
  uniqueId,
} from '@noctcore/auth/testing';
import { RedisCounterStore, RedisSessionStore, redisStores } from '../src';

const url = process.env.REDIS_URL;
const required = process.env.AUTH_REQUIRE_SERVICES === '1';

if (!url && required) throw new Error('REDIS_URL is required when AUTH_REQUIRE_SERVICES=1');

describe.skipIf(!url)('redis stores', () => {
  const redis = new Redis(url ?? 'redis://localhost:6390', {
    lazyConnect: false,
    maxRetriesPerRequest: 1,
  });

  const prefix = `${uniqueId('test')}:`;

  afterAll(async () => {
    const keys = await redis.keys(`${prefix}*`);

    if (keys.length > 0) await redis.del(...keys);

    await redis.quit();
  });

  const api = { describe, it };

  // A second connection, so the touch-versus-delete race really crosses connections.
  const second = new Redis(url ?? 'redis://localhost:6390', {
    lazyConnect: false,
    maxRetriesPerRequest: 1,
  });

  afterAll(async () => {
    await second.quit();
  });

  const sessions = new RedisSessionStore(redis, { prefix });

  runConformance(
    'redis session store',
    sessionStoreConformance(sessions, {
      secondary: new RedisSessionStore(second, { prefix }),
      epochTtlMs: (userId) => sessions.epochTtlRemaining(userId),
    }),
    api,
  );

  it('tells createAuth the longest session it guards', async () => {
    const { createAuth } = await import('@noctcore/auth');
    const { memoryStores, plainHasher } = await import('@noctcore/auth/testing');
    const memory = memoryStores();

    const config = {
      stores: {
        ...memory,
        sessions: new RedisSessionStore(redis, { prefix, epochTtl: '20d', maxSessionTtl: '7d' }),
      },
      password: { hasher: plainHasher() },
      mailer: { send: async () => undefined },
      secret: 'redis-test-secret-at-least-32-bytes-long',
      urls: { resetPassword: (t: string) => t },
    };

    expect(() => createAuth(config)).toThrow(/maxSessionTtl/u);
    expect(() => createAuth({ ...config, session: { rememberMeTtl: '7d' } })).not.toThrow();
  });

  it('refuses an epoch TTL that does not outlive the longest session', () => {
    expect(() => new RedisSessionStore(redis, { epochTtl: '30d' })).toThrow(
      /epochTtl must be longer/u,
    );

    expect(
      () => new RedisSessionStore(redis, { epochTtl: '20d', maxSessionTtl: '7d' }),
    ).not.toThrow();
  });

  runConformance(
    'redis counter store',
    counterStoreConformance(new RedisCounterStore(redis, { prefix })),
    api,
  );

  it('keeps every key it writes under a TTL', async () => {
    const { sessions, counters } = redisStores(redis, { prefix: `${prefix}ttl:` });
    const now = Date.now();
    const userId = uniqueId('user');

    await sessions.create(
      {
        id: uniqueId('s'),
        userId,
        createdAt: now,
        authenticatedAt: now,
        lastActiveAt: now,
        expiresAt: now + 60_000,
        idleTimeoutMs: 30_000,
        epoch: 0,
        rememberMe: false,
        persistentCookie: false,
        ip: '203.0.113.1',
        userAgent: 'test',
        attributes: {},
      },
      60_000,
    );

    await sessions.bumpEpoch(userId);
    await counters.increment('door', 60_000);
    const keys = await redis.keys(`${prefix}ttl:*`);

    expect(keys.length).toBe(4);

    for (const key of keys) expect(await redis.pttl(key)).toBeGreaterThan(0);
  });

  it('extends the epoch TTL when a later session is created', async () => {
    const store = new RedisSessionStore(redis, {
      prefix: `${prefix}epoch:`,
      epochTtl: '10s',
      maxSessionTtl: '5s',
    });

    const userId = uniqueId('user');

    await store.bumpEpoch(userId);
    await redis.pexpire(`${prefix}epoch:e:${userId}`, 1000);
    const now = Date.now();

    await store.create(
      {
        id: uniqueId('s'),
        userId,
        createdAt: now,
        authenticatedAt: now,
        lastActiveAt: now,
        expiresAt: now + 5000,
        idleTimeoutMs: 5000,
        epoch: 1,
        rememberMe: false,
        persistentCookie: false,
        ip: '203.0.113.1',
        userAgent: 'test',
        attributes: {},
      },
      5000,
    );

    expect(await redis.pttl(`${prefix}epoch:e:${userId}`)).toBeGreaterThan(5000);
  });
});
