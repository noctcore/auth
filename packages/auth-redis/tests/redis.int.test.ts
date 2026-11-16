import { Redis } from 'ioredis';
import { afterAll, describe, expect, it } from 'vitest';
import { counterStoreConformance, runConformance, sessionStoreConformance, uniqueId } from '@noctcore/auth/testing';
import { RedisCounterStore, RedisSessionStore, redisStores } from '../src';

const url = process.env.REDIS_URL;
const required = process.env.AUTH_REQUIRE_SERVICES === '1';
if (!url && required) throw new Error('REDIS_URL is required when AUTH_REQUIRE_SERVICES=1');

describe.skipIf(!url)('redis stores', () => {
  const redis = new Redis(url ?? 'redis://localhost:6390', { lazyConnect: false, maxRetriesPerRequest: 1 });
  const prefix = `${uniqueId('test')}:`;
  afterAll(async () => {
    const keys = await redis.keys(`${prefix}*`);
    if (keys.length > 0) await redis.del(...keys);
    await redis.quit();
  });

  const api = { describe, it };
  runConformance('redis session store', sessionStoreConformance(new RedisSessionStore(redis, { prefix })), api);
  runConformance('redis counter store', counterStoreConformance(new RedisCounterStore(redis, { prefix })), api);

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
    const store = new RedisSessionStore(redis, { prefix: `${prefix}epoch:`, epochTtl: '10s' });
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
