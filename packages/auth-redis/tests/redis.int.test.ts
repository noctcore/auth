import { Redis } from 'ioredis';
import { afterAll, describe, expect, it } from 'vitest';
import {
  counterStoreConformance,
  membershipStoreConformance,
  runConformance,
  sessionStoreConformance,
  twoFactorStoreConformance,
  uniqueId,
} from '@noctcore/auth/testing';
import {
  RedisCounterStore,
  RedisMembershipStore,
  RedisSessionStore,
  RedisTwoFactorStore,
  redisStores,
} from '../src';

const url = process.env['REDIS_URL'];
const required = process.env['AUTH_REQUIRE_SERVICES'] === '1';

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

  runConformance(
    'redis two-factor store',
    twoFactorStoreConformance(new RedisTwoFactorStore(redis, { prefix })),
    api,
  );

  runConformance(
    'redis membership store',
    membershipStoreConformance(new RedisMembershipStore(redis, { prefix })),
    api,
  );

  it('leaves one admin when two connections demote the last two admins at once', async () => {
    const one = new RedisMembershipStore(redis, { prefix });
    const two = new RedisMembershipStore(second, { prefix });
    const adminRoles = ['admin'];

    for (let round = 0; round < 20; round++) {
      const scope = uniqueId('scope');
      const [a, b] = [uniqueId('user'), uniqueId('user')];

      await one.addMember({ scope, userId: a, role: 'admin' });
      await one.addMember({ scope, userId: b, role: 'admin' });

      const results = await Promise.all([
        one.changeRole({ scope, userId: a, from: 'admin', to: 'member', adminRoles }),
        two.removeMember({ scope, userId: b, from: 'admin', adminRoles }),
      ]);

      expect([...results].sort()).toEqual(['done', 'last_admin']);
      expect((await one.listMembers(scope)).filter((m) => m.role === 'admin')).toHaveLength(1);
    }
  });

  it('keeps members without a TTL, under the ms: prefix', async () => {
    const store = new RedisMembershipStore(redis, { prefix });
    const scope = uniqueId('scope');

    await store.addMember({ scope, userId: 'u1', role: 'admin' });
    expect(await redis.pttl(`${prefix}ms:${scope}`)).toBe(-1);
  });

  it('keeps trusted devices and step-up proofs under a TTL at their expiry', async () => {
    const store = new RedisTwoFactorStore(redis, { prefix: `${prefix}tf-ttl:` });
    const now = Date.now();
    const userId = uniqueId('user');

    await store.addTrustedDevice(
      { userId, hash: uniqueId('d'), epoch: 0, createdAt: now, expiresAt: now + 60_000 },
      5,
    );

    await store.putStepUp({ sessionId: uniqueId('s'), userId, expiresAt: now + 30_000 });

    const keys = await redis.keys(`${prefix}tf-ttl:*`);

    expect(keys.length).toBe(3);

    for (const key of keys) {
      const ttl = await redis.pttl(key);

      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(60_000);
    }
  });

  it('drops a trusted device whose key expired from the user index on the next add', async () => {
    const store = new RedisTwoFactorStore(redis, { prefix: `${prefix}tf-gone:` });
    const now = Date.now();
    const userId = uniqueId('user');

    const first = {
      userId,
      hash: uniqueId('d'),
      epoch: 0,
      createdAt: now,
      expiresAt: now + 60_000,
    };

    const second = { ...first, hash: uniqueId('d'), createdAt: now + 1 };
    const third = { ...first, hash: uniqueId('d'), createdAt: now + 2 };

    await store.addTrustedDevice(first, 2);
    await redis.del(`${prefix}tf-gone:tf:d:${first.hash}`);
    await store.addTrustedDevice(second, 2);
    await store.addTrustedDevice(third, 2);

    expect(await store.findTrustedDevice(userId, second.hash)).toEqual(second);
    expect(await store.findTrustedDevice(userId, third.hash)).toEqual(third);
    expect(await redis.zcard(`${prefix}tf-gone:tf:du:${userId}`)).toBe(2);
  });

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
