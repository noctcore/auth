import { beforeEach, describe, expect, it } from 'vitest';

import { AuthConfigError } from '../../src/shared/errors';
import { silentLogger } from '../../src/ports/logger';
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
