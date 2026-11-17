// A045: turning two-factor off without a second-factor proof.
//
// An attacker with a session (stolen cookie) or the password turns the factor
// off, or prints new recovery codes, so the account is theirs without the
// phone from then on. A step-up that the password alone can satisfy is no
// step-up.
//
// Stopped by: plugins/two-factor/management.ts (turning off and new recovery codes need a
//   step-up), plugins/two-factor/step-up.ts (the proof is stored per session id; a
//   password re-entry re-issues the session under a new id with no proof; a trusted
//   device never records one).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, PASSWORD, twoFactorApp } from '../two-factor/setup';

describe('A045: turning two-factor off without a second-factor proof', () => {
  it('refuses to turn the factor off from a session with no recent proof', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(10 * 60_000);

    const fresh = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!fresh.ok) throw new Error(fresh.reason);

    const off = await t.auth.twoFactor.disable({ session: fresh.value.session, meta: meta() });

    expect(off).toMatchObject({
      ok: false,
      code: 'second_factor_required',
      reason: 'step_up_required',
    });

    expect((await t.store.findFactor(userId))?.confirmed).toBe(true);

    const codes = await t.auth.twoFactor.regenerateRecoveryCodes({
      session: fresh.value.session,
      meta: meta(),
    });

    expect(codes).toMatchObject({ ok: false, code: 'second_factor_required' });
  });

  it('refuses from a session that skipped the challenge with a trusted device', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    const first = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!first.ok) throw new Error(first.reason);

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'trusted-device', token: first.value.trustedDevice?.token },
      meta: meta(),
    });

    if (!skipped.ok) throw new Error(skipped.reason);

    const off = await t.auth.twoFactor.disable({
      session: skipped.value.session.session,
      meta: meta(),
    });

    expect(off).toMatchObject({ ok: false, code: 'second_factor_required' });
  });

  it('turns it off after a step-up with a code', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(10 * 60_000);

    const fresh = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!fresh.ok) throw new Error(fresh.reason);

    await t.auth.twoFactor.stepUp({
      session: fresh.value.session,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(
      (await t.auth.twoFactor.disable({ session: fresh.value.session, meta: meta() })).ok,
    ).toBe(true);
  });
});
