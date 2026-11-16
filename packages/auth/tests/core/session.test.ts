import { beforeEach, describe, expect, it } from 'vitest';

import { AuthConfigError } from '../../src/shared/errors';
import { sha256Hex } from '../../src/crypto/hash';
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
  it('stores only the SHA-256 of the token and stamps every field exactly', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    expect(minted.token).toMatch(/^[0-9a-f]{64}$/u);
    expect(await store.get(minted.token)).toBeNull();

    expect(await store.get(sha256Hex(minted.token))).toEqual({
      id: sha256Hex(minted.token),
      userId: 'u1',
      createdAt: clock.now(),
      authenticatedAt: clock.now(),
      lastActiveAt: clock.now(),
      expiresAt: clock.now() + 24 * 60 * MIN,
      idleTimeoutMs: 30 * MIN,
      epoch: 0,
      rememberMe: false,
      persistentCookie: false,
      ip: meta.ip,
      userAgent: 'test',
      attributes: { role: 'member' },
    });
  });

  it('gives remember-me sessions the long TTL and the long idle limit', async () => {
    const minted = await mintFor(manager(), 'u1', { rememberMe: true });

    if (!minted.ok) throw new Error('mint failed');

    expect(minted.session.expiresAt - clock.now()).toBe(30 * 24 * 60 * MIN);
    expect(minted.session.idleTimeoutMs).toBe(7 * 24 * 60 * MIN);
  });

  it('refuses and rolls back a mint whose epoch moved during the login', async () => {
    const m = manager();
    const epochBeforeCredentialRead = await m.readEpoch('u1');

    await m.revokeAll('u1'); // a password change commits while the login verifies the old hash
    const minted = await mintFor(m, 'u1', { epoch: epochBeforeCredentialRead });

    expect(minted).toEqual({ ok: false, reason: 'epoch_fence' });
    expect(await store.listByUser('u1')).toEqual([]);
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

  it('refuses every session minted before a revoke-all, even one the walk could not see', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    // Simulate a walk that missed the session: bump the epoch only.
    await store.bumpEpoch('u1');
    expect(await m.validate(minted.token)).toEqual({ ok: false, reason: 'epoch' });
  });

  it('refuses a session whose stored attributes no longer validate', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    await store.touch({ ...minted.session, attributes: { role: 7 } });
    expect(await m.validate(minted.token)).toEqual({ ok: false, reason: 'corrupt' });
  });

  it('reports a session revoked between the read and the touch as revoked', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    clock.advance(2 * MIN);
    const original = store.touch.bind(store);

    store.touch = async (session) => {
      await store.delete(session.userId, [session.id]);

      return original(session);
    };

    expect(await m.validate(minted.token)).toEqual({ ok: false, reason: 'revoked' });
    expect(await store.get(minted.session.id)).toBeNull();
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
