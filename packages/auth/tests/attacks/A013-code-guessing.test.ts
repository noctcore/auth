// A013: guessing a short code.
//
// A 6 to 9 digit reset or verification code is guessed, in parallel bursts or
// spread over many IPs, before it runs out.
//
// Stopped by: tokens/one-time-tokens.ts (attempt cap counted atomically before the compare;
//   the code is deleted when exhausted), flows/password-reset.ts (a per-address
//   budget across IPs, known or unknown address).
// Learn: Password reset (/auth/learn/password-reset/), Email verification (/auth/learn/email-verification/)
import { beforeEach, describe, expect, it } from 'vitest';

import { cryptoRandom } from '../../src/crypto/random';
import { manualClock, MemoryTokenStore, type ManualClock } from '../../src/testing';
import { OneTimeTokens } from '../../src/tokens/one-time-tokens';
import { codeFor, EMAIL, meta, queued, setup } from './support';

const secret = new TextEncoder().encode('server-secret-server-secret-0000');
let clock: ManualClock;
let store: MemoryTokenStore;
let tokens: OneTimeTokens;

beforeEach(() => {
  clock = manualClock();
  store = new MemoryTokenStore();
  tokens = new OneTimeTokens(store, clock, cryptoRandom, secret);
});

describe('A013: guessing a short code', () => {
  it('answers wrong codes and unknown addresses alike and caps attempts at 5', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);
    const code = await codeFor(t);
    const wrong = code === '00000000' ? '11111111' : '00000000';

    const ghost = await t.auth.verifyPasswordResetCode({
      email: 'ghost@example.com',
      code,
      meta: meta(),
    });

    expect(!ghost.ok && ghost.code).toBe('invalid_token');

    for (let i = 0; i < 5; i++) {
      const miss = await t.auth.verifyPasswordResetCode({
        email: EMAIL,
        code: wrong,
        meta: meta(`192.0.2.${i}`),
      });

      expect(!miss.ok && miss.code).toBe('invalid_token');
    }

    expect((await t.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() })).ok).toBe(
      false,
    );
  });

  it('counts guesses per address across IPs even with no code outstanding', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);

    // Sampling before any code exists, from five networks.
    for (let i = 0; i < 5; i++)
      await t.auth.verifyPasswordResetCode({
        email: EMAIL,
        code: '12345678',
        meta: meta(`192.0.2.${i}`),
      });

    const code = await codeFor(t);

    const blocked = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code,
      meta: meta('198.51.100.1'),
    });

    expect(!blocked.ok && blocked.code).toBe('rate_limited');

    const ghost = await t.auth.verifyPasswordResetCode({
      email: 'ghost@example.com',
      code,
      meta: meta('198.51.100.2'),
    });

    expect(!ghost.ok && ghost.code).toBe('invalid_token');
    t.clock.advance(15 * 60_000);
    const fresh = await codeFor(t);

    expect(
      (
        await t.auth.verifyPasswordResetCode({
          email: EMAIL,
          code: fresh,
          meta: meta('198.51.100.1'),
        })
      ).ok,
    ).toBe(true);
  });

  it('allows 5 wrong codes, then voids the code', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const code = env.mailer.last('verify-email')?.code ?? '';
    const wrong = code === '00000000' ? '11111111' : '00000000';

    for (let i = 0; i < 5; i++)
      await env.auth.verifyEmailCode({ session, code: wrong, meta: meta() });

    const late = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    expect(!late.ok && late.code).toBe('invalid_token');
  });

  it('caps parallel guesses at the attempt limit', async () => {
    const { code } = await tokens.issueCode('reset-code', 'u1', 60_000, 6);
    const wrong = code === '000000' ? '000001' : '000000';

    const results = await Promise.all(
      Array.from({ length: 30 }, () => tokens.redeemCode('reset-code', 'u1', wrong, 5)),
    );

    expect(results.filter((r) => r.status === 'mismatch')).toHaveLength(5);
  });
});
