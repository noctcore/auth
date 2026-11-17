// A043: a stolen trusted-device token outliving a password change.
//
// The owner notices a compromise and changes the password (or resets it, or
// signs out everywhere). The attacker kept the "remember this device" cookie
// from a session they had, and expects it to keep skipping the second factor
// once they learn the new password.
//
// Stopped by: plugins/two-factor/trusted-devices.ts (the device is bound to the revocation
//   epoch it was trusted at; every password change, reset and revoke-all bumps it),
//   plugins/two-factor/hooks.ts (those revocations also delete the devices), and a
//   device token never skips the password itself.
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, NEW_PASSWORD, PASSWORD, twoFactorApp, type TwoFactorApp } from '../two-factor/setup';

async function trustedDevice(t: TwoFactorApp, secret: string) {
  const done = await t.auth.twoFactor.verifyChallenge({
    challenge: (await t.challenged()).challenge,
    proof: { kind: 'totp', code: t.codeFor(secret) },
    rememberDevice: true,
    meta: meta(),
  });

  if (!done.ok || !done.value.trustedDevice) throw new Error('no device');

  t.nextStep();

  return { token: done.value.trustedDevice.token, session: done.value.session };
}

async function skipWith(t: TwoFactorApp, token: string, password = PASSWORD) {
  const login = await t.auth.login({ email: 'ada@example.com', password, meta: meta() });

  if (!login.ok || login.value.kind !== 'challenge') throw new Error('expected a challenge');

  return t.auth.twoFactor.verifyChallenge({
    challenge: login.value.challenge,
    proof: { kind: 'trusted-device', token },
    meta: meta(),
  });
}

describe('A043: a stolen trusted-device token outliving a password change', () => {
  it('dies with a password change', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const stolen = await trustedDevice(t, secret);

    expect((await skipWith(t, stolen.token)).ok).toBe(true);

    const changed = await t.auth.changePassword({
      session: stolen.session.session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      secondFactor: t.codeFor(secret),
      meta: meta(),
    });

    expect(changed.ok).toBe(true);

    expect(await skipWith(t, stolen.token, NEW_PASSWORD)).toMatchObject({
      ok: false,
      reason: 'device_not_trusted',
    });
  });

  it('dies with a password reset and with sign out everywhere, even if the store kept the row', async () => {
    const t = twoFactorApp();
    const { secret, session } = await t.enrolled();
    const stolen = await trustedDevice(t, secret);

    // The cleanup is a second line: the epoch alone must void the token.
    t.store.deleteTrustedDevices = async () => undefined;

    await t.auth.sessions.revokeAll({ session, meta: meta() });

    expect(await skipWith(t, stolen.token)).toMatchObject({
      ok: false,
      reason: 'device_not_trusted',
    });

    const again = await trustedDevice(t, secret);

    await t.auth.requestPasswordReset({ email: 'ada@example.com', meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const token = (t.mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';

    const reset = await t.auth.resetPassword({
      token,
      password: NEW_PASSWORD,
      secondFactor: t.codeFor(secret),
      meta: meta(),
    });

    expect(reset.ok).toBe(true);

    expect(await skipWith(t, again.token, NEW_PASSWORD)).toMatchObject({
      ok: false,
      reason: 'device_not_trusted',
    });
  });

  it('is deleted from the store by those revocations', async () => {
    const t = twoFactorApp();
    const { secret, session, userId } = await t.enrolled();

    await trustedDevice(t, secret);
    await t.auth.sessions.revokeAll({ session, meta: meta() });

    const devices = (t.store as unknown as { devices: Map<string, { userId: string }> }).devices;

    expect([...devices.values()].filter((d) => d.userId === userId)).toEqual([]);
  });

  it('never skips the password: a wrong password with a trusted device gets no challenge', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    await trustedDevice(t, secret);

    const login = await t.auth.login({
      email: 'ada@example.com',
      password: 'wrong passphrase!',
      meta: meta(),
    });

    expect(login).toMatchObject({ ok: false, code: 'invalid_credentials' });
  });

  it('dies when the factor is turned off', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const stolen = await trustedDevice(t, secret);
    const session = (await t.passed(secret)).session;

    await t.auth.twoFactor.disable({ session, meta: meta() });

    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    t.nextStep();

    expect(await skipWith(t, stolen.token)).toMatchObject({
      ok: false,
      reason: 'device_not_trusted',
    });
  });
});
