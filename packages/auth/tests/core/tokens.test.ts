import { beforeEach, describe, expect, it } from 'vitest';

import { cryptoRandom } from '../../src/crypto/random';
import { NO_SUCH_USER_ID } from '../../src/ports/stores';
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

describe('code redemption edges', () => {
  /** A code with no leading zero, so its number spells the same digits. */
  async function codeWithoutLeadingZero(userId = 'u1') {
    for (;;) {
      const { code } = await tokens.issueCode('reset-code', userId, 60_000, 6);

      if (!code.startsWith('0')) return code;
    }
  }

  it('refuses a code that is not exactly 6 to 9 digits without spending an attempt', async () => {
    const code = await codeWithoutLeadingZero();

    for (const malformed of [`x${code}`, `${code}x`, `${code}0123`, ` ${code}`, `${code}\n`])
      expect(await tokens.redeemCode('reset-code', 'u1', malformed, 5)).toEqual({
        status: 'unknown',
      });

    expect((await store.findByUser('reset-code', 'u1'))?.attempts).toBe(0);
    expect((await tokens.redeemCode('reset-code', 'u1', code, 5)).status).toBe('valid');
  });

  it('refuses the right digits passed as a number or any other non-string, and never throws', async () => {
    const code = await codeWithoutLeadingZero();

    for (const value of [Number(code), [code], { toString: () => code }, Symbol(code), null])
      expect(await tokens.redeemCode('reset-code', 'u1', value, 5)).toEqual({ status: 'unknown' });

    expect((await tokens.redeemCode('reset-code', 'u1', code, 5)).status).toBe('valid');
  });

  it('never matches an unknown user, even against a code stored under the placeholder id', async () => {
    const { code } = await tokens.issueCode('reset-code', NO_SUCH_USER_ID, 60_000, 6);

    expect(await tokens.redeemCode('reset-code', null, code, 5)).toEqual({ status: 'unknown' });
  });

  it('deletes an expired code and an exhausted one', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);

    clock.advance(60_000);

    expect(await tokens.redeemCode('reset-code', 'u1', code, 5)).toEqual({
      status: 'expired',
      namedUserId: 'u1',
    });

    expect(await store.findByUser('reset-code', 'u1')).toBeNull();

    const fresh = await tokens.issueCode('reset-code', 'u2', 60_000, 6);
    const wrong = fresh.code === '000000' ? '000001' : '000000';

    await tokens.redeemCode('reset-code', 'u2', wrong, 5);
    await tokens.redeemCode('reset-code', 'u2', wrong, 5);

    // A caller with a lower cap than the attempts already spent finds it exhausted.
    expect(await tokens.redeemCode('reset-code', 'u2', fresh.code, 2)).toEqual({
      status: 'exhausted',
      namedUserId: 'u2',
    });

    expect(await store.findByUser('reset-code', 'u2')).toBeNull();
  });
});

describe('link classification and revocation', () => {
  it('peeks an unknown link as exactly unknown, and a link that loses the consume race as consumed', async () => {
    expect(await tokens.peekLink('verify', 'a'.repeat(64))).toEqual({ status: 'unknown' });

    // An unknown link is answered from the lookup alone: nothing to consume.
    let consumes = 0;

    const counting = Object.assign(Object.create(store) as MemoryTokenStore, {
      consume: async () => (consumes++, null),
    });

    expect(
      await new OneTimeTokens(counting, clock, cryptoRandom, secret).redeemLink(
        'verify',
        'b'.repeat(64),
      ),
    ).toEqual({ status: 'unknown' });

    expect(consumes).toBe(0);

    const { token } = await tokens.issueLink('verify', 'u1', 60_000);

    const racing = Object.assign(Object.create(store) as MemoryTokenStore, {
      consume: async () => null,
    });

    const spied = new OneTimeTokens(racing, clock, cryptoRandom, secret);

    expect(await spied.redeemLink('verify', token)).toEqual({
      status: 'consumed',
      namedUserId: 'u1',
    });
  });

  it('revokes every token of the named purposes and leaves the rest', async () => {
    const reset = await tokens.issueLink('reset', 'u1', 60_000);
    const verify = await tokens.issueLink('verify', 'u1', 60_000);

    await tokens.revokeAll('u1', ['reset']);
    expect((await tokens.redeemLink('reset', reset.token)).status).toBe('unknown');
    expect((await tokens.redeemLink('verify', verify.token)).status).toBe('valid');
  });
});

describe('findLive', () => {
  it('returns the data of an unexpired token without consuming it, and nothing from its expiry on', async () => {
    const clock = manualClock();
    const tokens = new OneTimeTokens(new MemoryTokenStore(), clock, cryptoRandom, secret);

    const { token, expiresAt } = await tokens.issueLink('email-revert', 'u1', 60_000, {
      email: 'old@example.com',
    });

    expect(await tokens.findLive('email-revert', 'u1')).toEqual({
      data: { email: 'old@example.com' },
      expiresAt,
    });

    expect(await tokens.findLive('email-revert', 'u2')).toBeNull();

    clock.set(expiresAt - 1);
    expect(await tokens.findLive('email-revert', 'u1')).not.toBeNull();
    clock.set(expiresAt);
    expect(await tokens.findLive('email-revert', 'u1')).toBeNull();

    clock.set(expiresAt - 1);
    expect((await tokens.redeemLink('email-revert', token)).status).toBe('valid');
  });
});

describe('keyed markers', () => {
  it('finds a marker by its key until it expires, and moves it off another user', async () => {
    await tokens.putKeyed('email-reserved', 'u1', 'key-a', 60_000, { note: 'one' });

    expect(await tokens.findKeyed('email-reserved', 'key-a')).toEqual({
      userId: 'u1',
      data: { note: 'one' },
    });

    expect(await tokens.findKeyed('email-reserved', 'key-b')).toBeNull();
    expect(await tokens.findKeyed('other', 'key-a')).toBeNull();

    await tokens.putKeyed('email-reserved', 'u2', 'key-a', 120_000);

    expect(await tokens.findKeyed('email-reserved', 'key-a')).toEqual({ userId: 'u2', data: {} });
    expect(await store.findByUser('email-reserved', 'u1')).toBeNull();

    clock.advance(120_000 - 1);
    expect(await tokens.findKeyed('email-reserved', 'key-a')).not.toBeNull();
    clock.advance(1);
    expect(await tokens.findKeyed('email-reserved', 'key-a')).toBeNull();
  });
});

describe('extendLink', () => {
  it('moves a live link out, never in, and leaves unknown, malformed and expired links alone', async () => {
    const { token, expiresAt } = await tokens.issueLink('email-revert', 'u1', 60_000);

    await tokens.extendLink('email-revert', token, expiresAt - 1);
    expect((await store.findByUser('email-revert', 'u1'))?.expiresAt).toBe(expiresAt);

    await tokens.extendLink('email-revert', token, expiresAt);
    expect((await store.findByUser('email-revert', 'u1'))?.expiresAt).toBe(expiresAt);

    await tokens.extendLink('email-revert', token, expiresAt + 1);
    expect((await store.findByUser('email-revert', 'u1'))?.expiresAt).toBe(expiresAt + 1);

    await tokens.extendLink('email-revert', 42, expiresAt + 5);
    await tokens.extendLink('other', token, expiresAt + 5);
    expect((await store.findByUser('email-revert', 'u1'))?.expiresAt).toBe(expiresAt + 1);

    clock.set(expiresAt + 1);
    await tokens.extendLink('email-revert', token, expiresAt + 10);
    expect((await store.findByUser('email-revert', 'u1'))?.expiresAt).toBe(expiresAt + 1);

    clock.set(expiresAt);
    expect((await tokens.redeemLink('email-revert', token)).status).toBe('valid');
  });
});
