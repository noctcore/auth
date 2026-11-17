// A007: reusing a password reset token.
//
// A reset link or ticket is replayed after use, used after it expired, raced from
// two tabs, or a raw code is presented where only the ticket it buys is accepted.
//
// Stopped by: tokens/one-time-tokens.ts (atomic single-use consume, expiry checked after the
//   consume, purpose-bound tokens), flows/password-reset.ts.
// Learn: Password reset (/auth/learn/password-reset/)
import { beforeEach, describe, expect, it } from 'vitest';

import { cryptoRandom } from '../../src/crypto/random';
import { manualClock, MemoryTokenStore, type ManualClock } from '../../src/testing';
import { OneTimeTokens } from '../../src/tokens/one-time-tokens';
import { codeFor, EMAIL, linkFor, meta, NEW_PASSWORD, queued } from './support';

const secret = new TextEncoder().encode('server-secret-server-secret-0000');
let clock: ManualClock;
let store: MemoryTokenStore;
let tokens: OneTimeTokens;

beforeEach(() => {
  clock = manualClock();
  store = new MemoryTokenStore();
  tokens = new OneTimeTokens(store, clock, cryptoRandom, secret);
});

describe('A007: reusing a password reset token', () => {
  it('refuses an expired link and a replayed one', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    const link = await linkFor(t);

    t.clock.advance(3_600_000);

    expect(
      (await t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(false);

    const fresh = await linkFor(t);

    await t.auth.resetPassword({ token: fresh, password: NEW_PASSWORD, meta: meta() });

    const replay = await t.auth.resetPassword({
      token: fresh,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!replay.ok && replay.code).toBe('invalid_token');
  });

  it('lets exactly one of two concurrent resets win', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    const link = await linkFor(t);

    const results = await Promise.all([
      t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() }),
      t.auth.resetPassword({ token: link, password: 'yet another passphrase', meta: meta() }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('refuses a raw code where a ticket is expected', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);
    const code = await codeFor(t);

    expect(
      (await t.auth.resetPassword({ token: code, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(false);
  });

  it('lets exactly one of many concurrent redemptions win', async () => {
    const { token } = await tokens.issueLink('verify', 'u1', 60_000);

    const results = await Promise.all(
      Array.from({ length: 20 }, () => tokens.redeemLink('verify', token)),
    );

    expect(results.filter((r) => r.status === 'valid')).toHaveLength(1);
  });
});
