import { beforeEach, describe, expect, it } from 'vitest';

import { sha256Hex } from '../../src/hash';
import { cryptoRandom } from '../../src/random';
import { manualClock, MemoryTokenStore, type ManualClock } from '../../src/testing';
import { NO_SUCH_USER_ID } from '../../src/stores';
import { OneTimeTokens } from '../../src/tokens';

const secret = new TextEncoder().encode('server-secret-server-secret-0000');
let clock: ManualClock;
let store: MemoryTokenStore;
let tokens: OneTimeTokens;

beforeEach(() => {
  clock = manualClock();
  store = new MemoryTokenStore();
  tokens = new OneTimeTokens(store, clock, cryptoRandom, secret);
});

describe('links', () => {
  it('stores only the SHA-256 and redeems exactly once', async () => {
    const { token } = await tokens.issueLink('verify', 'u1', 60_000, { email: 'a@example.com' });

    expect(await store.find('verify', token)).toBeNull();
    expect(await store.find('verify', sha256Hex(token))).not.toBeNull();

    expect(await tokens.redeemLink('verify', token)).toEqual({
      status: 'valid',
      userId: 'u1',
      data: { email: 'a@example.com' },
    });

    expect(await tokens.redeemLink('verify', token)).toEqual({ status: 'unknown' });
  });

  it('is bound to its purpose', async () => {
    const { token } = await tokens.issueLink('verify', 'u1', 60_000);

    expect(await tokens.redeemLink('reset', token)).toEqual({ status: 'unknown' });
  });

  it('refuses an expired link and removes it', async () => {
    const { token } = await tokens.issueLink('verify', 'u1', 60_000);

    clock.advance(60_000);

    expect(await tokens.redeemLink('verify', token)).toEqual({
      status: 'expired',
      namedUserId: 'u1',
    });

    expect(await store.findByUser('verify', 'u1')).toBeNull();
  });

  it('lets exactly one of many concurrent redemptions win', async () => {
    const { token } = await tokens.issueLink('verify', 'u1', 60_000);

    const results = await Promise.all(
      Array.from({ length: 20 }, () => tokens.redeemLink('verify', token)),
    );

    expect(results.filter((r) => r.status === 'valid')).toHaveLength(1);
  });

  it('peeks without consuming', async () => {
    const { token } = await tokens.issueLink('reset', 'u1', 60_000);

    expect((await tokens.peekLink('reset', token)).status).toBe('valid');
    expect((await tokens.redeemLink('reset', token)).status).toBe('valid');
  });

  it('replaces the previous link of the same purpose', async () => {
    const first = await tokens.issueLink('reset', 'u1', 60_000);

    await tokens.issueLink('reset', 'u1', 60_000);
    expect((await tokens.redeemLink('reset', first.token)).status).toBe('unknown');
  });
});

describe('codes', () => {
  it('stores an HMAC bound to purpose and user, not a plain hash', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);
    const stored = await store.findByUser('reset-code', 'u1');

    expect(stored?.hash).not.toBe(sha256Hex(code));
    expect(stored?.hash).toMatch(/^[0-9a-f]{64}$/u);
  });

  it('redeems a correct code once', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);

    expect((await tokens.redeemCode('reset-code', 'u1', code, 5)).status).toBe('valid');
    expect((await tokens.redeemCode('reset-code', 'u1', code, 5)).status).toBe('unknown');
  });

  it('deletes the code after the last allowed wrong guess', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);
    const wrong = code === '000000' ? '000001' : '000000';

    for (let i = 0; i < 5; i++)
      expect((await tokens.redeemCode('reset-code', 'u1', wrong, 5)).status).toBe('mismatch');

    expect((await tokens.redeemCode('reset-code', 'u1', code, 5)).status).toBe('unknown');
  });

  it('caps parallel guesses at the attempt limit', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);
    const wrong = code === '000000' ? '000001' : '000000';

    const results = await Promise.all(
      Array.from({ length: 30 }, () => tokens.redeemCode('reset-code', 'u1', wrong, 5)),
    );

    expect(results.filter((r) => r.status === 'mismatch')).toHaveLength(5);
  });

  it('refuses an expired code, a malformed code and an unknown user alike', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);

    expect((await tokens.redeemCode('reset-code', null, code, 5)).status).toBe('unknown');
    expect((await tokens.redeemCode('reset-code', 'u1', '12ab56', 5)).status).toBe('unknown');
    clock.advance(60_000);
    expect((await tokens.redeemCode('reset-code', 'u1', code, 5)).status).toBe('expired');
  });

  it('cannot be used without a server secret', async () => {
    const noSecret = new OneTimeTokens(store, clock, cryptoRandom, undefined);

    await expect(noSecret.issueCode('reset-code', 'u1', 60_000, 6)).rejects.toThrow(/secret/u);
  });

  it('makes the same store lookup for an unknown user as for a known one', async () => {
    const lookups: string[] = [];

    const spy = Object.assign(Object.create(store) as MemoryTokenStore, {
      findByUser: (purpose: string, userId: string) => (
        lookups.push(userId),
        store.findByUser(purpose, userId)
      ),
    });

    const spied = new OneTimeTokens(spy, clock, cryptoRandom, secret);

    await spied.redeemCode('reset', null, '12345678', 5);
    await spied.redeemCode('reset', 'user-1', '12345678', 5);
    expect(lookups).toEqual([NO_SUCH_USER_ID, 'user-1']);
  });
});
