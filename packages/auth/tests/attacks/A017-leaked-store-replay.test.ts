// A017: replaying secrets from a leaked store.
//
// A database dump, a Redis snapshot or a backup leaks; the attacker presents
// what it holds as session tokens, reset links or codes.
//
// Stopped by: session/session-manager.ts and tokens/one-time-tokens.ts store only the
//   SHA-256 of a token, and codes only as an HMAC under the server secret, bound
//   to purpose and user (crypto/hash.ts).
// Learn: Sessions and expiry (/auth/learn/sessions-and-expiry/)
import { beforeEach, describe, expect, it } from 'vitest';

import { sha256Hex } from '../../src/crypto/hash';
import { cryptoRandom } from '../../src/crypto/random';
import { silentLogger } from '../../src/ports/logger';
import { SessionManager } from '../../src/session/session-manager';
import type { SessionOptions } from '../../src/session/session-types';
import {
  manualClock,
  MemorySessionStore,
  MemoryTokenStore,
  type ManualClock,
} from '../../src/testing';
import { OneTimeTokens } from '../../src/tokens/one-time-tokens';

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

const secret = new TextEncoder().encode('server-secret-server-secret-0000');
let tokenStore: MemoryTokenStore;
let tokens: OneTimeTokens;

beforeEach(() => {
  tokenStore = new MemoryTokenStore();
  tokens = new OneTimeTokens(tokenStore, clock, cryptoRandom, secret);
});

describe('A017: replaying secrets from a leaked store', () => {
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

  it('stores only the SHA-256 and redeems exactly once', async () => {
    const { token } = await tokens.issueLink('verify', 'u1', 60_000, { email: 'a@example.com' });

    expect(await tokenStore.find('verify', token)).toBeNull();
    expect(await tokenStore.find('verify', sha256Hex(token))).not.toBeNull();

    expect(await tokens.redeemLink('verify', token)).toEqual({
      status: 'valid',
      userId: 'u1',
      data: { email: 'a@example.com' },
    });

    expect(await tokens.redeemLink('verify', token)).toEqual({ status: 'unknown' });
  });

  it('stores an HMAC bound to purpose and user, not a plain hash', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);
    const stored = await tokenStore.findByUser('reset-code', 'u1');

    expect(stored?.hash).not.toBe(sha256Hex(code));
    expect(stored?.hash).toMatch(/^[0-9a-f]{64}$/u);
  });

  it('stores a code as an HMAC under the server secret, so a leaked table cannot be reversed without it', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);
    const stored = await tokenStore.findByUser('reset-code', 'u1');
    const otherSecret = new TextEncoder().encode('another-secret-another-secret-00');

    const elsewhere = new OneTimeTokens(
      new MemoryTokenStore(),
      manualClock(),
      cryptoRandom,
      otherSecret,
    );

    const { code: sameDigits } = await elsewhere.issueCode('reset-code', 'u1', 60_000, 6);

    expect(stored?.hash).not.toBe(sha256Hex(code));
    expect(stored?.hash).not.toBe(sha256Hex(`reset-code:u1:${code}`));
    expect(sameDigits).toMatch(/^\d{6}$/u);
  });
});
