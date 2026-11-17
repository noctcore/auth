// Guards in the Redis session store that need no server: a session that would
// outlive its revocation epoch is refused, and a value that is not JSON is
// read as no session rather than thrown.
import { describe, expect, it } from 'vitest';
import { AuthConfigError, type StoredSession } from '@noctcore/auth';
import { RedisSessionStore } from '../src';

const DAY = 86_400_000;

const session: StoredSession = {
  id: 'a'.repeat(64),
  userId: 'u1',
  createdAt: 0,
  authenticatedAt: 0,
  lastActiveAt: 0,
  expiresAt: 100 * DAY,
  idleTimeoutMs: DAY,
  epoch: 0,
  rememberMe: true,
  persistentCookie: true,
  ip: '203.0.113.5',
  userAgent: 'test',
  attributes: {},
};

describe('RedisSessionStore guards', () => {
  it('refuses a session longer than its epoch can guard, before touching Redis', async () => {
    const store = new RedisSessionStore({} as never);

    await expect(store.create(session, 91 * DAY)).rejects.toThrow(AuthConfigError);
  });

  it('refuses an epoch TTL that does not outlast the longest session', () => {
    expect(() => new RedisSessionStore({} as never, { epochTtl: '30d' })).toThrow(AuthConfigError);
  });

  it('reads a stored value that is not JSON as no session', async () => {
    const store = new RedisSessionStore({ get: async () => '{not json' } as never);

    expect(await store.get(session.id)).toBeNull();
  });
});
