// A039: reusing a login challenge.
//
// The challenge token that passed once (from a log, a proxy, the browser
// history) is presented again, with a later code, to open a second session
// without the password. Or an old challenge is kept and used after a new
// login, or after it should have expired.
//
// Stopped by: plugins/two-factor/challenge.ts (the passing code spends the challenge by
//   an atomic consume; a challenge lasts 5 minutes; a new login replaces it),
//   tokens/one-time-tokens.ts (single-use consume, expiry checked after it).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, twoFactorApp } from '../two-factor/setup';

describe('A039: reusing a login challenge', () => {
  it('refuses a challenge that already passed, even with a new valid code', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    expect(
      (
        await t.auth.twoFactor.verifyChallenge({
          challenge,
          proof: { kind: 'totp', code: t.codeFor(secret) },
          meta: meta(),
        })
      ).ok,
    ).toBe(true);

    t.nextStep();

    const again = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(again).toMatchObject({
      ok: false,
      code: 'invalid_second_factor',
      reason: 'challenge_unknown',
    });
  });

  it('refuses a challenge replaced by a newer login, and one older than 5 minutes', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const old = await t.challenged();

    await t.challenged();

    const replaced = await t.auth.twoFactor.verifyChallenge({
      challenge: old.challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(!replaced.ok && replaced.reason).toBe('challenge_unknown');

    const late = await t.challenged();

    t.clock.advance(5 * 60_000);

    const expired = await t.auth.twoFactor.verifyChallenge({
      challenge: late.challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(!expired.ok && expired.reason).toBe('challenge_expired');
  });

  it('refuses a challenge from another client', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    const stolen = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: { ...meta('198.51.100.1'), userAgent: 'attacker' },
    });

    expect(!stolen.ok && stolen.reason).toBe('client_mismatch');
  });
});
