import { beforeEach, describe, expect, it } from 'vitest';

import { AuthConfigError } from '../../src/shared/errors';
import { silentLogger, type Logger } from '../../src/ports/logger';
import { cryptoRandom } from '../../src/crypto/random';
import { SessionManager } from '../../src/session/session-manager';
import type { SessionOptions } from '../../src/session/session-types';
import { manualClock, MemorySessionStore, type ManualClock } from '../../src/testing';

const meta = { ip: '203.0.113.5', userAgent: 'test' };
const MIN = 60_000;

interface Attrs {
  role: string;
}

const attributes = {
  parse(value: unknown): Attrs {
    if (typeof value !== 'object' || value === null || typeof (value as Attrs).role !== 'string')
      throw new Error('bad');

    return { role: (value as Attrs).role };
  },
};

let clock: ManualClock;
let store: MemorySessionStore;

function manager(options: SessionOptions<Attrs> = {}) {
  return new SessionManager<Attrs>(
    store,
    { attributes, ...options },
    clock,
    cryptoRandom,
    silentLogger,
  );
}

const mintFor = (
  m: SessionManager<Attrs>,
  userId = 'u1',
  extra: { rememberMe?: boolean; epoch?: number } = {},
) =>
  m.mint({
    userId,
    attributes: { role: 'member' },
    rememberMe: extra.rememberMe ?? false,
    persistentCookie: false,
    authenticatedAt: clock.now(),
    meta,
    ...(extra.epoch === undefined ? {} : { epoch: extra.epoch }),
  });

beforeEach(() => {
  clock = manualClock();
  store = new MemorySessionStore(clock);
});

describe('SessionManager.mint', () => {
  it('gives remember-me sessions the long TTL and the long idle limit', async () => {
    const minted = await mintFor(manager(), 'u1', { rememberMe: true });

    if (!minted.ok) throw new Error('mint failed');

    expect(minted.session.expiresAt - clock.now()).toBe(30 * 24 * 60 * MIN);
    expect(minted.session.idleTimeoutMs).toBe(7 * 24 * 60 * MIN);
  });

  it('evicts the oldest sessions beyond the cap and reports them', async () => {
    const m = manager({ maxPerUser: 2 });
    const first = await mintFor(m);

    clock.advance(1000);
    await mintFor(m);
    clock.advance(1000);
    const third = await mintFor(m);

    if (!first.ok || !third.ok) throw new Error('mint failed');

    expect(third.evicted).toEqual([first.session.id]);
    expect((await m.listActive('u1')).map((s) => s.id)).not.toContain(first.session.id);
  });

  it('validates its options', () => {
    expect(() => manager({ maxPerUser: 0 })).toThrow(AuthConfigError);
    expect(() => manager({ idleTimeout: '1m', touchInterval: '2m' })).toThrow(AuthConfigError);
  });
});

describe('SessionManager.validate', () => {
  it('refuses malformed and unknown tokens', async () => {
    const m = manager();

    expect(await m.validate('nope')).toEqual({ ok: false, reason: 'malformed' });
    expect(await m.validate('a'.repeat(64))).toEqual({ ok: false, reason: 'unknown' });
  });

  it('touches at most once per interval, never extending the absolute expiry', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    clock.advance(30_000);
    const early = await m.validate(minted.token);

    expect(early.ok && early.session.lastActiveAt).toBe(minted.session.lastActiveAt);
    clock.advance(31_000);
    const later = await m.validate(minted.token);

    expect(later.ok && later.session.lastActiveAt).toBe(clock.now());
    expect(later.ok && later.session.expiresAt).toBe(minted.session.expiresAt);
  });

  it('does not touch when asked not to (background traffic)', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    clock.advance(25 * MIN);
    await m.validate(minted.token, { touch: false });
    clock.advance(6 * MIN);
    expect(await m.validate(minted.token)).toEqual({ ok: false, reason: 'idle' });
  });

  it('ends an idle session and reaps it', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    clock.advance(30 * MIN);
    expect(await m.validate(minted.token)).toEqual({ ok: false, reason: 'idle' });
    expect(await store.listByUser('u1')).toEqual([]);
  });

  it('keeps an active session alive until its absolute expiry', async () => {
    const m = manager({ absoluteTtl: '2h' });
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    for (let i = 0; i < 7; i++) {
      clock.advance(15 * MIN);
      expect((await m.validate(minted.token)).ok).toBe(true);
    }

    clock.advance(15 * MIN);
    expect((await m.validate(minted.token)).ok).toBe(false);
  });

  it('refuses a session whose stored attributes no longer validate', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    await store.touch({ ...minted.session, attributes: { role: 7 } });
    expect(await m.validate(minted.token)).toEqual({ ok: false, reason: 'corrupt' });
  });
});

describe('SessionManager revocation', () => {
  it('revokeAll keeps a session minted after the bump', async () => {
    const m = manager();
    const before = await mintFor(m);
    const ids = await m.revokeAll('u1');
    const after = await mintFor(m);

    if (!before.ok || !after.ok) throw new Error('mint failed');

    expect(ids).toEqual([before.session.id]);
    expect((await m.validate(after.token)).ok).toBe(true);
  });

  it('revoke only deletes sessions owned by that user', async () => {
    const m = manager();
    const mine = await mintFor(m, 'u1');
    const theirs = await mintFor(m, 'u2');

    if (!mine.ok || !theirs.ok) throw new Error('mint failed');

    expect(await m.revoke('u1', [theirs.session.id])).toEqual([]);
    expect((await m.validate(theirs.token)).ok).toBe(true);
    expect(await m.revoke('u1', [mine.session.id])).toEqual([mine.session.id]);
  });
});

describe('SessionManager options and edges', () => {
  it('picks the idle timeout per session when it is a function, and checks a fixed one at startup', async () => {
    const perSession = manager({
      idleTimeout: ({ rememberMe }) => (rememberMe ? '2h' : '10m'),
      touchInterval: '15m',
    });

    const short = await mintFor(perSession);
    const long = await mintFor(perSession, 'u1', { rememberMe: true });

    if (!short.ok || !long.ok) throw new Error('mint failed');

    expect(short.session.idleTimeoutMs).toBe(10 * MIN);
    expect(long.session.idleTimeoutMs).toBe(120 * MIN);

    const fixed = await mintFor(manager({ idleTimeout: '5m', touchInterval: '1m' }), 'u2', {
      rememberMe: true,
    });

    if (!fixed.ok) throw new Error('mint failed');

    expect(fixed.session.idleTimeoutMs).toBe(5 * MIN);
    expect(() => manager({ idleTimeout: '5m', touchInterval: '5m' })).toThrow(AuthConfigError);
  });

  it('keeps every session when the per-user cap is off, and refuses a cap below one', async () => {
    const m = manager({ maxPerUser: null });

    for (let i = 0; i < 12; i++) {
      const minted = await mintFor(m);

      if (!minted.ok) throw new Error('mint failed');

      expect(minted.evicted).toEqual([]);
    }

    expect(await m.listActive('u1')).toHaveLength(12);
    expect(() => manager({ maxPerUser: 0 })).toThrow(AuthConfigError);
    expect(() => manager({ maxPerUser: 1.5 })).toThrow(AuthConfigError);
  });

  it('refuses and reaps a stored session past its absolute expiry even if the store still returns it', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    const deleted: string[] = [];

    const stale = Object.assign(Object.create(store) as MemorySessionStore, {
      get: async () => ({ ...minted.session, expiresAt: clock.now() }),
      delete: async (_userId: string, ids: readonly string[]) => {
        deleted.push(...ids);
      },
    });

    const reading = new SessionManager<Attrs>(
      stale,
      { attributes },
      clock,
      cryptoRandom,
      silentLogger,
    );

    expect(await reading.validate(minted.token)).toEqual({ ok: false, reason: 'expired' });
    expect(deleted).toEqual([minted.session.id]);
  });

  it('logs out by token only for a well-formed token it knows', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    expect(await m.revokeToken('not a token')).toBeNull();
    expect(await m.revokeToken('0'.repeat(64))).toBeNull();
    expect((await m.validate(minted.token)).ok).toBe(true);
    expect((await m.revokeToken(minted.token))?.id).toBe(minted.session.id);
    expect(await store.get(minted.session.id)).toBeNull();
  });
});

/** The store, with every delete it is asked for recorded (including empty ones). */
function recordingDeletes() {
  const deletes: string[][] = [];
  const original = store.delete.bind(store);

  store.delete = async (userId, ids) => {
    deletes.push([...ids]);

    return original(userId, ids);
  };

  return deletes;
}

describe('SessionManager.listActive', () => {
  it('lists only unexpired, non-idle sessions on the current epoch, and reaps exactly the rest', async () => {
    const m = manager({ idleTimeout: '30m', touchInterval: '1m' });
    const live = await mintFor(m);
    const expired = await mintFor(m);
    const idle = await mintFor(m);
    const oldEpoch = await mintFor(m);

    if (!live.ok || !expired.ok || !idle.ok || !oldEpoch.ok) throw new Error('mint failed');

    // Exactly at the boundary: a session that expires now, or whose idle limit
    // ends now, is dead, the same verdict validate gives.
    await store.touch({ ...expired.session, expiresAt: clock.now() });
    await store.touch({ ...idle.session, lastActiveAt: clock.now() - 30 * MIN });
    await store.touch({ ...oldEpoch.session, epoch: -1 });

    const deletes = recordingDeletes();

    expect((await m.listActive('u1')).map((s) => s.id)).toEqual([live.session.id]);
    expect(deletes).toEqual([[expired.session.id, idle.session.id, oldEpoch.session.id]]);
    expect(await store.listByUser('u1')).toHaveLength(1);
  });

  it('makes no delete when every session is live', async () => {
    const m = manager();

    await mintFor(m);
    await mintFor(m);

    const deletes = recordingDeletes();

    expect(await m.listActive('u1')).toHaveLength(2);
    expect(deletes).toEqual([]);
  });
});

describe('SessionManager cap and revocation edges', () => {
  it('evicts the oldest by creation time whatever order the store lists them in', async () => {
    const m = manager({ maxPerUser: 2 });
    const first = await mintFor(m);

    clock.advance(1000);
    const second = await mintFor(m);

    if (!first.ok || !second.ok) throw new Error('mint failed');

    const listByUser = store.listByUser.bind(store);

    store.listByUser = async (userId) => (await listByUser(userId)).reverse();
    clock.advance(1000);

    const third = await mintFor(m);

    if (!third.ok) throw new Error('mint failed');

    expect(third.evicted).toEqual([first.session.id]);
  });

  it('evicts several at once, oldest first, when a tighter cap meets more sessions', async () => {
    const roomy = manager({ maxPerUser: 4 });
    const ids: string[] = [];

    for (let i = 0; i < 3; i++) {
      const minted = await mintFor(roomy);

      if (!minted.ok) throw new Error('mint failed');

      ids.push(minted.session.id);
      clock.advance(1000);
    }

    const latest = await mintFor(manager({ maxPerUser: 2 }));

    if (!latest.ok) throw new Error('mint failed');

    expect(latest.evicted).toEqual([ids[0], ids[1]]);
  });

  it('reports a session two racing mints both chose to evict from only one of them', async () => {
    const m = manager({ maxPerUser: 1 });
    const oldest = await mintFor(m);

    if (!oldest.ok) throw new Error('mint failed');

    clock.advance(1000);

    // Hold both mints after their write until both have listed, so both see
    // the oldest session and both delete it.
    const listByUser = store.listByUser.bind(store);
    let waiting: (() => void)[] = [];

    store.listByUser = async (userId) => {
      const listed = await listByUser(userId);

      await new Promise<void>((resolve) => {
        waiting.push(resolve);

        if (waiting.length < 2) return;

        for (const release of waiting) release();

        waiting = [];
      });

      return listed;
    };

    const [a, b] = await Promise.all([mintFor(m), mintFor(m)]);

    if (!a.ok || !b.ok) throw new Error('mint failed');

    const reported = [...a.evicted, ...b.evicted];

    expect(reported.filter((id) => id === oldest.session.id)).toHaveLength(1);
    expect(new Set(reported).size).toBe(reported.length);

    const live = new Set((await listByUser('u1')).map((s) => s.id));
    const gone = [oldest.session.id, a.session.id, b.session.id].filter((id) => !live.has(id));

    expect([...reported].sort()).toEqual(gone.sort());
  });

  it('reports every id it chose when the store does not say which it removed', async () => {
    const m = manager({ maxPerUser: 1 });
    const first = await mintFor(m);

    if (!first.ok) throw new Error('mint failed');

    const remove = store.delete.bind(store);

    // A store written against the older contract: delete resolves to nothing.
    store.delete = async (userId: string, ids: readonly string[]) => {
      await remove(userId, ids);

      return undefined as never;
    };

    clock.advance(1000);
    const second = await mintFor(m);

    if (!second.ok) throw new Error('mint failed');

    expect(second.evicted).toEqual([first.session.id]);
  });

  it('evicts nothing under the cap, and accepts a cap of one', async () => {
    const atCap = manager({ maxPerUser: 2 });

    await mintFor(atCap, 'u3');

    const deletes = recordingDeletes();

    await mintFor(atCap, 'u3');
    expect(deletes).toEqual([]);

    const m = manager({ maxPerUser: 3 });

    await mintFor(m);

    const second = await mintFor(m);

    if (!second.ok) throw new Error('mint failed');

    expect(second.evicted).toEqual([]);
    expect(await m.listActive('u1')).toHaveLength(2);

    const single = manager({ maxPerUser: 1 });
    const replaced = await mintFor(single, 'u2');
    const latest = await mintFor(single, 'u2');

    if (!replaced.ok || !latest.ok) throw new Error('mint failed');

    expect(latest.evicted).toEqual([replaced.session.id]);
  });

  it('names the option it refuses', () => {
    expect(() => manager({ maxPerUser: 0 })).toThrow(
      'session.maxPerUser must be a positive integer or null',
    );

    expect(() => manager({ idleTimeout: '1m', touchInterval: '2m' })).toThrow(
      'session.touchInterval must be shorter than the idle timeout',
    );
  });

  it('stores an empty user agent when the request has none', async () => {
    const minted = await manager().mint({
      userId: 'u1',
      attributes: { role: 'member' },
      rememberMe: false,
      persistentCookie: false,
      authenticatedAt: clock.now(),
      meta: { ip: meta.ip },
    });

    if (!minted.ok) throw new Error('mint failed');

    expect(minted.session.userAgent).toBe('');
  });

  it('touches once the full interval has passed, not a millisecond later', async () => {
    const m = manager({ idleTimeout: '30m', touchInterval: '1m' });
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    clock.advance(MIN);

    const validated = await m.validate(minted.token);

    expect(validated.ok && validated.session.lastActiveAt).toBe(clock.now());
  });

  it('reaps a session whose attributes no longer validate', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    await store.touch({ ...minted.session, attributes: { role: 7 } });
    await m.validate(minted.token);
    expect(await store.listByUser('u1')).toEqual([]);
  });

  it('reclaims the rows of every revoked session, keeping one stamped with the new epoch', async () => {
    // No cap, so the racing mint does not reap the old session itself.
    const m = manager({ maxPerUser: null });
    const before = await mintFor(m);

    if (!before.ok) throw new Error('mint failed');

    // A login that read the new epoch lands between the bump and the walk.
    const listByUser = store.listByUser.bind(store);
    let racing: Awaited<ReturnType<typeof mintFor>> | undefined;

    store.listByUser = async (userId) => {
      store.listByUser = listByUser;
      racing = await mintFor(m, userId, { epoch: await store.getEpoch(userId) });

      return listByUser(userId);
    };

    expect(await m.revokeAll('u1')).toEqual([before.session.id]);
    expect(await store.get(before.session.id)).toBeNull();

    expect(racing?.ok && (await store.listByUser('u1')).map((s) => s.id)).toEqual(
      racing?.ok ? [racing.session.id] : null,
    );
  });

  it('asks the store for nothing it does not need: no empty deletes, no lookup for a malformed token', async () => {
    const m = manager();
    const deletes = recordingDeletes();
    let gets = 0;
    const get = store.get.bind(store);

    store.get = async (id) => (gets++, get(id));

    expect(await m.revokeAll('nobody')).toEqual([]);
    expect(await m.revoke('nobody', ['x'])).toEqual([]);
    expect(await m.revokeToken({ toString: () => 'a'.repeat(64) })).toBeNull();
    expect(deletes).toEqual([]);
    expect(gets).toBe(0);
  });
});

describe('SessionManager warnings', () => {
  it('tells the operator, by user id only, about a lost epoch fence and a session with bad attributes', async () => {
    const warnings: [string, Record<string, unknown> | undefined][] = [];

    const logger: Logger = {
      warn: (message, context) => void warnings.push([message, context]),
      error: () => undefined,
    };

    const m = new SessionManager<Attrs>(store, { attributes }, clock, cryptoRandom, logger);
    const epoch = await m.readEpoch('u1');

    await m.revokeAll('u1');
    await mintFor(m, 'u1', { epoch });

    const minted = await mintFor(m, 'u2');

    if (!minted.ok) throw new Error('mint failed');

    await store.touch({ ...minted.session, attributes: { role: 7 } });
    await m.validate(minted.token);

    expect(warnings).toEqual([
      ['Session mint lost the epoch fence; a revocation landed mid-login', { userId: 'u1' }],
      ['Session attributes failed validation; treating the session as invalid', { userId: 'u2' }],
    ]);
  });
});

describe('SessionManager.findActive', () => {
  it('finds a live session by id without touching or reaping anything', async () => {
    const m = manager({ idleTimeout: '30m' });
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    expect(await m.findActive(minted.session.id)).toEqual(minted.session);
    expect(await m.findActive('f'.repeat(64))).toBeNull();
  });

  it('refuses an idle session, and one from before a revoke-all, that the store still holds', async () => {
    const m = manager({ idleTimeout: '30m' });
    const idle = await mintFor(m);

    if (!idle.ok) throw new Error('mint failed');

    clock.advance(30 * MIN);
    expect(await m.findActive(idle.session.id)).toBeNull();
    expect(await store.get(idle.session.id)).not.toBeNull();

    const stale = await mintFor(m, 'u2');

    if (!stale.ok) throw new Error('mint failed');

    await store.bumpEpoch('u2');
    expect(await m.findActive(stale.session.id)).toBeNull();
    expect(await store.get(stale.session.id)).not.toBeNull();
  });
});
