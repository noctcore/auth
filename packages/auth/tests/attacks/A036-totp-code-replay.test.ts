// A036: replaying a TOTP code in the same time step.
//
// A code is valid for 30 seconds (and one step either side). Someone who sees
// it typed, or reads it from a log or a proxy, sends it again while it is
// still in its window: a second login, a step-up, a password reset.
//
// Stopped by: plugins/two-factor/proofs.ts (a matching code is accepted only if its
//   step moves the stored last step forward), ports/two-factor.ts (`advanceStep` is a
//   compare-and-set, checked by the conformance suite).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, NEW_PASSWORD, twoFactorApp } from '../two-factor/setup';

describe('A036: replaying a TOTP code in the same time step', () => {
  it('accepts a code once: the same code on a second challenge is refused', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const code = t.codeFor(secret);
    const first = await t.challenged();
    const second = await t.challenged('ada@example.com', { userAgent: 'vitest' });

    // A new login replaced the first challenge; take a fresh one for each use.
    expect(first.challenge).not.toBe(second.challenge);

    const used = await t.auth.twoFactor.verifyChallenge({
      challenge: second.challenge,
      proof: { kind: 'totp', code },
      meta: meta(),
    });

    expect(used.ok).toBe(true);

    const replay = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code },
      meta: meta(),
    });

    expect(replay).toMatchObject({
      ok: false,
      code: 'invalid_second_factor',
      reason: 'code_replayed',
    });
  });

  it('refuses an older code once a newer one was accepted', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const older = t.codeFor(secret);
    const newer = t.codeFor(secret, 1);

    expect(
      (
        await t.auth.twoFactor.verifyChallenge({
          challenge: (await t.challenged()).challenge,
          proof: { kind: 'totp', code: newer },
          meta: meta(),
        })
      ).ok,
    ).toBe(true);

    const stale = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: older },
      meta: meta(),
    });

    expect(!stale.ok && stale.reason).toBe('code_replayed');
  });

  it('shares the spent step across doors: a code used at login cannot step up, or reset a password', async () => {
    const t = twoFactorApp();
    const { secret, session } = await t.enrolled();
    const code = t.codeFor(secret);

    await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code },
      meta: meta(),
    });

    const step = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code },
      meta: meta(),
    });

    expect(!step.ok && step.reason).toBe('code_replayed');

    await t.auth.requestPasswordReset({ email: 'ada@example.com', meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const token = (t.mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';

    const reset = await t.auth.resetPassword({
      token,
      password: NEW_PASSWORD,
      secondFactor: code,
      meta: meta(),
    });

    expect(!reset.ok && reset.reason).toBe('reset_reset_second_factor_code_replayed');
  });
});
