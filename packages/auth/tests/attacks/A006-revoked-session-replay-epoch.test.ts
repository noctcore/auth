// A006: replaying a revoked session.
//
// A session revoked by "sign out everywhere" or a password change keeps working:
// because the revocation walk missed it, because a login that read the old
// credential minted it mid-revocation, or because a touch wrote it back.
//
// Stopped by: session/session-manager.ts: the epoch fence (bump first, then walk; every
//   session carries the epoch read before its credential; the mint re-reads it)
//   and the update-only-if-exists touch.
// Learn: Revocation races and the epoch fence (/auth/learn/revocation-races/)
import { beforeEach, describe, expect, it } from 'vitest';

import { cryptoRandom } from '../../src/crypto/random';
import { silentLogger } from '../../src/ports/logger';
import { SessionManager } from '../../src/session/session-manager';
import type { SessionOptions } from '../../src/session/session-types';
import { manualClock, MemorySessionStore, plainHasher, type ManualClock } from '../../src/testing';
import { EMAIL, meta as flowMeta, PASSWORD, registered } from './support';

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

describe('A006: replaying a revoked session', () => {
  it('refuses every session minted before a revoke-all, even one the walk could not see', async () => {
    const m = manager();
    const minted = await mintFor(m);

    if (!minted.ok) throw new Error('mint failed');

    // Simulate a walk that missed the session: bump the epoch only.
    await store.bumpEpoch('u1');
    expect(await m.validate(minted.token)).toEqual({ ok: false, reason: 'epoch' });
  });

  it('refuses and rolls back a mint whose epoch moved during the login', async () => {
    const m = manager();
    const epochBeforeCredentialRead = await m.readEpoch('u1');

    await m.revokeAll('u1'); // a password change commits while the login verifies the old hash
    const minted = await mintFor(m, 'u1', { epoch: epochBeforeCredentialRead });

    expect(minted).toEqual({ ok: false, reason: 'epoch_fence' });
    expect(await store.listByUser('u1')).toEqual([]);
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

  it('refuses the session when a revocation lands between the password check and the mint', async () => {
    const base = plainHasher();
    let revokeDuringVerify: (() => Promise<void>) | null = null;

    const hasher = {
      ...base,
      verify: async (hash: string, password: string) => {
        if (revokeDuringVerify) await revokeDuringVerify();

        return base.verify(hash, password);
      },
    };

    const env = await registered({ password: { hasher, breachCheck: false } });
    const user = await env.stores.users.findCredentialByEmail(EMAIL as never);

    revokeDuringVerify = async () => {
      await env.auth.context.sessions.revokeAll(user?.id ?? '');
    };

    const result = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: flowMeta() });

    expect(!result.ok && result.reason).toBe('epoch_fence');
  });
});
