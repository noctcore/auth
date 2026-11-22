import { describe, expect, it, vi } from 'vitest';

import {
  adoptLegacySessions,
  AuthConfigError,
  clearsSessionCookie,
  systemClock,
  type LegacySession,
} from '../../src';
import { sha256Hex } from '../../src/crypto/hash';
import { generateToken } from '../../src/crypto/random';
import type { SessionStore } from '../../src/ports/stores';
import { manualClock, MemorySessionStore } from '../../src/testing';
import { meta, setup } from '../flows/setup';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** An app's own session table, keyed by the SHA-256 of the cookie token. */
function legacyStore() {
  const rows = new Map<string, LegacySession>();

  return {
    rows,
    take: vi.fn(async (id: string) => {
      const row = rows.get(id) ?? null;

      rows.delete(id);

      return row;
    }),
  };
}

/** A session store whose `create` lands `ms` later, like a write on a database round trip. */
function slowCreates(store: SessionStore, ms: number): SessionStore {
  return {
    create: async (session, ttlMs) => {
      await new Promise<void>((resolve) => setTimeout(resolve, ms));
      await store.create(session, ttlMs);
    },
    get: (id) => store.get(id),
    touch: (session) => store.touch(session),
    delete: (userId, ids) => store.delete(userId, ids),
    listByUser: (userId) => store.listByUser(userId),
    getEpoch: (userId) => store.getEpoch(userId),
    bumpEpoch: (userId) => store.bumpEpoch(userId),
  };
}

function legacyRow(userId: string, now: number, overrides: Partial<LegacySession> = {}) {
  return {
    userId,
    createdAt: now - HOUR,
    authenticatedAt: now - HOUR,
    lastActiveAt: now - 60_000,
    expiresAt: now + DAY,
    idleTimeoutMs: 7 * DAY,
    rememberMe: true,
    ip: '203.0.113.7',
    userAgent: 'legacy browser',
    ...overrides,
  } satisfies LegacySession;
}

describe('adoptLegacySessions', () => {
  it('reads a legacy session once, rewrites it in the package format and removes the legacy record', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const inner = new MemorySessionStore(clock);
    const legacy = legacyStore();
    const store = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock });
    const token = generateToken();
    const id = sha256Hex(token);
    const now = clock.now();

    legacy.rows.set(id, legacyRow('user-1', now));

    const first = await store.get(id);

    expect(first).toEqual({
      id,
      userId: 'user-1',
      createdAt: now - HOUR,
      authenticatedAt: now - HOUR,
      lastActiveAt: now - 60_000,
      expiresAt: now + DAY,
      idleTimeoutMs: 7 * DAY,
      epoch: 0,
      rememberMe: true,
      persistentCookie: true,
      ip: '203.0.113.7',
      userAgent: 'legacy browser',
      attributes: {},
    });

    // Rewritten: the package's own store now holds it, under its user.
    expect(await inner.get(id)).toEqual(first);
    expect((await inner.listByUser('user-1')).map((s) => s.id)).toEqual([id]);
    // The legacy record is gone.
    expect(legacy.rows.has(id)).toBe(false);

    // The second read is served from the package's store alone.
    expect(await store.get(id)).toEqual(first);
    expect(legacy.take).toHaveBeenCalledTimes(1);
  });

  it('keeps the TTL of the legacy session, never longer', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const inner = new MemorySessionStore(clock);
    const legacy = legacyStore();
    const store = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock });
    const id = sha256Hex(generateToken());

    legacy.rows.set(id, legacyRow('user-1', clock.now(), { expiresAt: clock.now() + HOUR }));
    await store.get(id);

    clock.advance(HOUR);

    expect(await inner.get(id)).toBeNull();
  });

  it('caps the expiry at maxTtl after the session was created, and at the store limit', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const now = clock.now();
    const legacy = legacyStore();
    const id = sha256Hex(generateToken());
    const inner = new MemorySessionStore(clock);
    const store = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '7d', clock });

    legacy.rows.set(
      id,
      legacyRow('user-1', now, { createdAt: now - DAY, expiresAt: now + 365 * DAY }),
    );

    expect((await store.get(id))?.expiresAt).toBe(now + 6 * DAY);

    const limited: SessionStore = Object.assign(new MemorySessionStore(clock), {
      maxSessionTtlMs: 2 * DAY,
      epochTtlMs: 3 * DAY,
    });

    const capped = adoptLegacySessions(limited, { take: legacy.take, maxTtl: '7d', clock });

    expect(capped.maxSessionTtlMs).toBe(2 * DAY);
    expect(capped.epochTtlMs).toBe(3 * DAY);

    legacy.rows.set(
      id,
      legacyRow('user-1', now, { createdAt: now - DAY, expiresAt: now + 365 * DAY }),
    );

    expect((await capped.get(id))?.expiresAt).toBe(now + DAY);
  });

  it('drops an expired, future-dated or malformed legacy record, and logs the malformed one', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const now = clock.now();
    const inner = new MemorySessionStore(clock);
    const legacy = legacyStore();
    const logger = { warn: vi.fn(), error: vi.fn() };
    const store = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock, logger });

    const rows: Partial<LegacySession>[] = [
      { expiresAt: now },
      { createdAt: now - 31 * DAY, expiresAt: now + DAY },
      { createdAt: now + 1 },
      { expiresAt: Number.NaN },
      { idleTimeoutMs: 0 },
      { userId: '' },
      { userId: 42 as unknown as string },
      { rememberMe: 'yes' as unknown as boolean },
    ];

    for (const overrides of rows) {
      const id = sha256Hex(generateToken());

      legacy.rows.set(id, legacyRow('user-1', now, overrides));

      expect(await store.get(id)).toBeNull();
      expect(await inner.get(id)).toBeNull();
      expect(legacy.rows.has(id)).toBe(false);
    }

    expect(await inner.listByUser('user-1')).toEqual([]);
    expect(logger.warn).toHaveBeenCalledTimes(6);
    expect(logger.warn.mock.calls.at(-2)?.[1]).toEqual({ userId: undefined });
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain('legacy browser');
  });

  it('clamps a future last-active or authentication time to now', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const now = clock.now();
    const legacy = legacyStore();
    const id = sha256Hex(generateToken());

    const store = adoptLegacySessions(new MemorySessionStore(clock), {
      take: legacy.take,
      maxTtl: '30d',
      clock,
    });

    legacy.rows.set(
      id,
      legacyRow('user-1', now, { authenticatedAt: now + DAY, lastActiveAt: now + DAY }),
    );

    expect(await store.get(id)).toMatchObject({ authenticatedAt: now, lastActiveAt: now });
  });

  it('adopts once when two requests race on one cookie, and both see the session', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const inner = new MemorySessionStore(clock);
    const legacy = legacyStore();
    const store = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock });
    const id = sha256Hex(generateToken());

    legacy.rows.set(id, legacyRow('user-1', clock.now()));

    const [a, b] = await Promise.all([store.get(id), store.get(id)]);

    expect(a?.id).toBe(id);
    expect(b?.id).toBe(id);
    expect(await inner.listByUser('user-1')).toHaveLength(1);
  });

  it('lets the losing request see the session a slow store is still writing, on another instance', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const inner = slowCreates(new MemorySessionStore(clock), 10);
    const legacy = legacyStore();
    // Two app instances over the same stores, as two processes would be.
    const first = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock });
    const second = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock });
    const id = sha256Hex(generateToken());

    legacy.rows.set(id, legacyRow('user-1', clock.now()));

    const [a, b] = await Promise.all([first.get(id), second.get(id)]);

    expect(a?.id).toBe(id);
    expect(b?.id).toBe(id);
    expect(legacy.take).toHaveBeenCalledTimes(2);
  });

  it('fails closed when the winning write is slower than the wait', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const inner = slowCreates(new MemorySessionStore(clock), 300);
    const legacy = legacyStore();
    const first = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock });
    const second = adoptLegacySessions(inner, { take: legacy.take, maxTtl: '30d', clock });
    const id = sha256Hex(generateToken());

    legacy.rows.set(id, legacyRow('user-1', clock.now()));

    const [a, b] = await Promise.all([first.get(id), second.get(id)]);

    expect(a?.id).toBe(id);
    expect(b).toBeNull();
    // The next request finds the session the winner wrote.
    expect((await second.get(id))?.id).toBe(id);
  });

  it('refuses the losing request as adopting, which keeps its cookie, and a dead token as for good', async () => {
    const legacy = legacyStore();
    const t = setup();
    const slow = slowCreates(t.stores.sessions, 300);

    const wrap = () =>
      adoptLegacySessions(slow, { take: legacy.take, maxTtl: '30d', clock: t.clock });

    // Two app instances over the same stores, as two processes would be.
    const first = setup({ stores: { ...t.stores, sessions: wrap() }, clock: t.clock } as never);
    const second = setup({ stores: { ...t.stores, sessions: wrap() }, clock: t.clock } as never);
    const user = await first.signedInUser('legacy@example.com');
    const token = generateToken();

    legacy.rows.set(sha256Hex(token), legacyRow(user.session.userId, t.clock.now()));

    const [won, lost] = await Promise.all([
      first.auth.validateRequest({ token, meta: meta() }),
      second.auth.validateRequest({ token, meta: meta() }),
    ]);

    expect(won.ok).toBe(true);
    expect(lost).toMatchObject({ ok: false, code: 'session_expired', reason: 'session_adopting' });
    expect(clearsSessionCookie(won)).toBe(false);
    expect(clearsSessionCookie(lost)).toBe(false);

    // The cookie it kept finds the adopted session on the next request.
    expect((await second.auth.validateRequest({ token, meta: meta() })).ok).toBe(true);

    // A malformed token, and a legacy record that is dropped, are refused for good.
    const malformed = await second.auth.validateRequest({ token: 'not-a-token', meta: meta() });
    const expiredToken = generateToken();

    legacy.rows.set(
      sha256Hex(expiredToken),
      legacyRow(user.session.userId, t.clock.now(), { expiresAt: t.clock.now() }),
    );

    const expired = await second.auth.validateRequest({ token: expiredToken, meta: meta() });

    expect(malformed).toMatchObject({ ok: false, reason: 'session_malformed' });
    expect(expired).toMatchObject({ ok: false, reason: 'session_unknown' });
    expect([malformed, expired].map(clearsSessionCookie)).toEqual([true, true]);
  });

  it('never reports adopting without the wrapper: an unknown token is refused for good', async () => {
    const t = setup();
    const result = await t.auth.validateRequest({ token: generateToken(), meta: meta() });

    expect(result).toMatchObject({ ok: false, reason: 'session_unknown' });
    expect(clearsSessionCookie(result)).toBe(true);
  });

  it('answers null for a token no store knows', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const legacy = legacyStore();

    const store = adoptLegacySessions(new MemorySessionStore(clock), {
      take: legacy.take,
      maxTtl: '30d',
      clock,
    });

    expect(await store.get(sha256Hex(generateToken()))).toBeNull();

    // Without a logger, a malformed record is dropped quietly.
    const id = sha256Hex(generateToken());

    legacy.rows.set(id, legacyRow('user-1', clock.now(), { idleTimeoutMs: -1 }));

    expect(await store.get(id)).toBeNull();
  });

  it('reads the system clock when none is given', async () => {
    const legacy = legacyStore();

    const store = adoptLegacySessions(new MemorySessionStore(systemClock), {
      take: legacy.take,
      maxTtl: '30d',
    });

    const id = sha256Hex(generateToken());

    legacy.rows.set(id, legacyRow('user-1', Date.now()));

    expect((await store.get(id))?.id).toBe(id);
  });

  it('refuses a maxTtl of zero', () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));

    expect(() =>
      adoptLegacySessions(new MemorySessionStore(clock), {
        take: async () => null,
        maxTtl: 0,
        clock,
      }),
    ).toThrow(AuthConfigError);
  });

  it('serves a legacy cookie through createAuth, then from the package store', async () => {
    const legacy = legacyStore();

    const t = setup();

    const sessions = adoptLegacySessions(t.stores.sessions, {
      take: legacy.take,
      maxTtl: '30d',
      clock: t.clock,
    });

    const app = setup({ stores: { ...t.stores, sessions }, clock: t.clock } as never);
    const user = await app.signedInUser('legacy@example.com');
    const token = generateToken();

    legacy.rows.set(sha256Hex(token), legacyRow(user.session.userId, t.clock.now()));

    const first = await app.auth.validateRequest({ token, meta: meta() });
    const second = await app.auth.validateRequest({ token, meta: meta() });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(legacy.take).toHaveBeenCalledTimes(1);
    expect((await app.auth.sessions.list(user.session)).length).toBe(2);
  });
});
