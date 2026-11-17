// A049: acting on a stale or borrowed second-factor proof.
//
// A step-up proved once is kept forever, carried over to a re-issued session,
// shared between sessions of the same user, or minted by the password alone,
// so a stolen session (or a stolen password) passes a sensitive action without
// the phone.
//
// Stopped by: plugins/two-factor/step-up.ts (a proof per session id, with an expiry on the
//   server clock, 10 minutes by default; checked together with fresh authentication read
//   from the live session in the store, core/auth-core.ts `requireFreshLiveSession`; a
//   re-issued session starts without one), plugins/two-factor/challenge.ts (a trusted
//   device records none).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, PASSWORD, twoFactorApp } from '../two-factor/setup';

describe('A049: acting on a stale or borrowed second-factor proof', () => {
  it('lapses after the step-up window, on the server clock', async () => {
    const t = twoFactorApp({}, { session: { freshAuthAge: '1h' } });
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    // passed() moved to the next time step (30 s) after the proof was recorded.
    t.clock.advance(10 * 60_000 - 30_000 - 1);
    expect((await t.auth.twoFactor.requireStepUp(session)).ok).toBe(true);
    t.clock.advance(1);

    expect(await t.auth.twoFactor.requireStepUp(session)).toMatchObject({
      ok: false,
      code: 'second_factor_required',
    });
  });

  it('is not carried to a session re-issued by a password re-entry', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    expect((await t.auth.twoFactor.requireStepUp(session)).ok).toBe(true);

    const reauth = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!reauth.ok) throw new Error(reauth.reason);

    // The rotation ended the old session, and its proof with it.
    expect(await t.auth.twoFactor.requireStepUp(session)).toMatchObject({
      ok: false,
      code: 'session_expired',
    });

    expect(await t.auth.twoFactor.requireStepUp(reauth.value.session)).toMatchObject({
      ok: false,
      code: 'second_factor_required',
    });
  });

  it('belongs to one session: another session of the same user has none', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const first = (await t.passed(secret)).session;

    const other = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'trusted-device', token: other.ok ? other.value.trustedDevice?.token : '' },
      meta: meta(),
    });

    if (!skipped.ok) throw new Error(skipped.reason);

    expect((await t.auth.twoFactor.requireStepUp(first)).ok).toBe(true);
    expect((await t.auth.twoFactor.requireStepUp(skipped.value.session.session)).ok).toBe(false);
  });

  it('still needs fresh authentication: an old session with a new proof is refused', async () => {
    const t = twoFactorApp({ stepUpWindow: '1h' });
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(11 * 60_000);

    await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(await t.auth.twoFactor.requireStepUp(session)).toMatchObject({
      ok: false,
      code: 'fresh_auth_required',
    });

    // Claiming a fresh proof on the object does not help: freshness is read
    // from the live session in the store.
    const claimed = { ...session, authenticatedAt: t.clock.now() };

    expect(await t.auth.twoFactor.requireStepUp(claimed)).toMatchObject({
      ok: false,
      code: 'fresh_auth_required',
    });
  });

  it('refuses a password change with a stale proof and no code', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(10 * 60_000);

    const changed = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: 'another long passphrase',
      meta: meta(),
    });

    expect(changed).toMatchObject({ ok: false, code: 'second_factor_required' });
  });
});
