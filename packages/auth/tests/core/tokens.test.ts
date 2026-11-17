import { beforeEach, describe, expect, it } from 'vitest';

import { cryptoRandom } from '../../src/crypto/random';
import { manualClock, MemoryTokenStore, type ManualClock } from '../../src/testing';
import { OneTimeTokens } from '../../src/tokens/one-time-tokens';

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
});

describe('edges', () => {
  it('refuses a malformed link without asking the store', async () => {
    let finds = 0;

    const spy = Object.assign(Object.create(store) as MemoryTokenStore, {
      find: async () => (finds++, null),
    });

    const spied = new OneTimeTokens(spy, clock, cryptoRandom, secret);

    expect(await spied.redeemLink('verify', 'not-a-token')).toEqual({ status: 'unknown' });
    expect(await spied.peekLink('verify', 42)).toEqual({ status: 'unknown' });
    expect(finds).toBe(0);
  });

  it('answers consumed when a correct code loses the consume race', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);

    const racing = Object.assign(Object.create(store) as MemoryTokenStore, {
      consume: async () => null,
    });

    const spied = new OneTimeTokens(racing, clock, cryptoRandom, secret);

    expect(await spied.redeemCode('reset-code', 'u1', code, 5)).toEqual({
      status: 'consumed',
      namedUserId: 'u1',
    });
  });
});
