import { describe, expect, it } from 'vitest';

import { EMAIL, meta, PASSWORD, twoFactorApp } from './setup';

const OTHER = 'grace@example.com';

describe('challenge: a sign-in the app authenticated itself', () => {
  it('challenges an enrolled user and finishes with a second-factor session', async () => {
    const t = twoFactorApp();
    const { userId, secret } = await t.enrolled();
    const started = await t.auth.twoFactor.challenge({ userId, rememberMe: true, meta: meta() });

    if (!started.ok || !started.value) throw new Error('expected a challenge');

    expect(started.value.methods).toEqual(['totp', 'recovery-code', 'trusted-device']);

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: started.value.challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    if (!done.ok) throw new Error(done.reason);

    expect(done.value.session.session.rememberMe).toBe(true);

    expect(t.audit.events).toContainEqual(
      expect.objectContaining({
        type: 'session.created',
        data: { via: 'second-factor', rememberMe: true },
      }),
    );

    expect(t.audit.events).toContainEqual(
      expect.objectContaining({
        type: 'login.challenge',
        userId,
        data: { methods: 'totp,recovery-code,trusted-device', via: 'app' },
      }),
    );
  });

  it('answers null for a user without a factor and for an unknown user', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn(OTHER);

    expect(await t.auth.twoFactor.challenge({ userId: session.userId, meta: meta() })).toEqual({
      ok: true,
      value: null,
    });

    expect(await t.auth.twoFactor.challenge({ userId: 'no-such-user', meta: meta() })).toEqual({
      ok: true,
      value: null,
    });
  });

  it('gives a required user without a factor an enrollment challenge', async () => {
    const t = twoFactorApp({ required: () => true });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const user = await t.stores.users.findCredentialByEmail(EMAIL as never);
    const started = await t.auth.twoFactor.challenge({ userId: user?.id ?? '', meta: meta() });

    expect(started.ok && started.value?.methods).toEqual(['enroll']);
  });

  it('refuses the verify when the sessions were revoked after the epoch it carries', async () => {
    const t = twoFactorApp();
    const { userId, secret } = await t.enrolled();
    const epoch = await t.auth.context.sessions.readEpoch(userId);
    const started = await t.auth.twoFactor.challenge({ userId, epoch, meta: meta() });

    if (!started.ok || !started.value) throw new Error('expected a challenge');

    await t.auth.context.revokeAllSessions(userId, 'password-reset');

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: started.value.challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(done.ok).toBe(false);
  });

  it('lets a trusted device through, as after a password login', async () => {
    const t = twoFactorApp();
    const { userId, secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    const trusted = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!trusted.ok || !trusted.value.trustedDevice) throw new Error('expected a device');

    const started = await t.auth.twoFactor.challenge({ userId, meta: meta() });

    if (!started.ok || !started.value) throw new Error('expected a challenge');

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: started.value.challenge,
      proof: { kind: 'trusted-device', token: trusted.value.trustedDevice.token },
      meta: meta(),
    });

    expect(done.ok).toBe(true);
  });

  it('counts each start on the per-IP limit', async () => {
    const t = twoFactorApp({ perIp: { limit: 2, window: '15m' } });
    const { userId } = await t.enrolled();

    await t.auth.twoFactor.challenge({ userId, meta: meta('198.51.100.9') });
    await t.auth.twoFactor.challenge({ userId, meta: meta('198.51.100.9') });

    expect(await t.auth.twoFactor.challenge({ userId, meta: meta('198.51.100.9') })).toMatchObject({
      ok: false,
      code: 'rate_limited',
    });
  });
});
