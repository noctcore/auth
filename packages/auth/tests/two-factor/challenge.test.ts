import { describe, expect, it } from 'vitest';

import { EMAIL, meta, PASSWORD, twoFactorApp, unknownToken } from './setup';

describe('the two-factor login challenge', () => {
  it('turns a correct password into a challenge, with no session and no device cookie yet', async () => {
    const t = twoFactorApp();

    const { userId } = await t.enrolled();
    const before = (await t.stores.sessions.listByUser(userId)).length;
    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect((await t.stores.sessions.listByUser(userId)).length).toBe(before);
    expect(login.ok && login.value.kind).toBe('challenge');
    expect(login.ok && 'session' in login.value).toBe(false);

    expect(login.ok && login.value.kind === 'challenge' && login.value.methods).toEqual([
      'totp',
      'recovery-code',
      'trusted-device',
    ]);

    expect(login.ok && login.value.kind === 'challenge' && login.value.challenge).toMatch(
      /^[0-9a-f]{64}$/u,
    );
  });

  it('leaves out the trusted-device method when trusted devices are off', async () => {
    const t = twoFactorApp({ trustedDevices: false });

    await t.enrolled();

    expect((await t.challenged()).methods).toEqual(['totp', 'recovery-code']);
  });

  it('finishes the login with a code, carrying remember-me, and records a step-up', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();

    const login = await t.auth.login({
      email: EMAIL,
      password: PASSWORD,
      rememberMe: true,
      meta: meta(),
    });

    if (!login.ok || login.value.kind !== 'challenge') throw new Error('challenge');

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: login.value.challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    if (!done.ok) throw new Error(done.reason);

    expect(done.value.session.session.userId).toBe(userId);
    expect(done.value.session.session.rememberMe).toBe(true);
    expect(done.value.recoveryCodes).toBeNull();
    expect(done.value.trustedDevice).toBeNull();
    expect(await t.sessionOf(done.value.session.token)).not.toBeNull();

    expect(await t.auth.twoFactor.requireStepUp(done.value.session.session)).toEqual({
      ok: true,
      value: undefined,
    });

    expect(t.audit.events.find((e) => e.type === 'two_factor.verified')?.data).toEqual({
      method: 'totp',
    });
  });

  it('accepts the code of the step before and after now, and nothing further', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    // The step before now must not be the one enrollment spent.
    t.nextStep();

    for (const steps of [-1, 1]) {
      const { challenge } = await t.challenged();

      const done = await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'totp', code: t.codeFor(secret, steps) },
        meta: meta(),
      });

      expect(done.ok).toBe(true);
      t.clock.advance(90_000);
    }

    for (const steps of [-2, 2]) {
      const { challenge } = await t.challenged();

      const done = await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'totp', code: t.codeFor(secret, steps) },
        meta: meta(),
      });

      expect(!done.ok && done.reason).toBe('wrong_code');
    }
  });

  it('accepts a code typed with spaces', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();
    const code = t.codeFor(secret);

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: ` ${code.slice(0, 3)} ${code.slice(3)} ` },
      meta: meta(),
    });

    expect(done.ok).toBe(true);
  });

  it('accepts a recovery code once and mails the owner how many are left', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, userId } = await t.enrolled();
    const first = recoveryCodes[0] ?? '';
    const { challenge } = await t.challenged();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'recovery-code', code: first.toUpperCase().replace('-', ' ') },
      meta: meta(),
    });

    expect(done.ok).toBe(true);

    expect(done.ok && (await t.auth.twoFactor.requireStepUp(done.value.session.session)).ok).toBe(
      true,
    );

    expect(await t.store.countRecoveryCodes(userId)).toBe(9);

    await Promise.resolve();
    expect(t.mailer.last('recovery-code-used')).toMatchObject({ to: EMAIL, userId, remaining: 9 });

    expect(t.audit.events.find((e) => e.type === 'two_factor.recovery_code_used')?.data).toEqual({
      remaining: 9,
    });
  });

  it('skips the mail but keeps the row when the user vanished as the code was spent', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, session } = await t.enrolled();

    t.stores.users.findById = async () => null;

    const step = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'recovery-code', code: recoveryCodes[0] ?? '' },
      meta: meta(),
    });

    expect(step.ok).toBe(true);
    await Promise.resolve();
    expect(t.mailer.last('recovery-code-used')).toBeUndefined();
    expect(t.audit.types()).toContain('two_factor.recovery_code_used');
  });

  it('refuses a malformed recovery code and one of another user', async () => {
    const t = twoFactorApp();
    const ada = await t.enrolled();

    await t.enrolled('grace@example.com');

    const { challenge } = await t.challenged('grace@example.com');

    for (const [code, reason] of [
      ['not a code', 'malformed_recovery_code'],
      [ada.recoveryCodes[0] ?? '', 'wrong_recovery_code'],
    ] as const) {
      const done = await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'recovery-code', code },
        meta: meta(),
      });

      expect(done).toMatchObject({ ok: false, code: 'invalid_second_factor', reason });
    }
  });

  it('spends the challenge on success: a second redemption is refused', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

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

  it('refuses a challenge from another client, an expired one and an unknown one', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    const verify = (c: string, userAgent = 'vitest') =>
      t.auth.twoFactor.verifyChallenge({
        challenge: c,
        proof: { kind: 'totp', code: t.codeFor(secret) },
        meta: { ...meta(), userAgent },
      });

    expect(await verify(challenge, 'another browser')).toMatchObject({
      ok: false,
      reason: 'client_mismatch',
    });

    expect(await verify(unknownToken())).toMatchObject({ ok: false, reason: 'challenge_unknown' });

    t.clock.advance(5 * 60_000);

    expect(await verify(challenge)).toMatchObject({ ok: false, reason: 'challenge_expired' });
  });

  it('spends a challenge after five codes, right or wrong', async () => {
    const t = twoFactorApp({ attempts: { limit: 100, window: '15m' } });
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    const verify = (code: string) =>
      t.auth.twoFactor.verifyChallenge({ challenge, proof: { kind: 'totp', code }, meta: meta() });

    for (let i = 0; i < 5; i++) expect((await verify('000000')).ok).toBe(false);

    expect(await verify(t.codeFor(secret))).toMatchObject({
      ok: false,
      reason: 'challenge_exhausted',
    });
  });

  it('refuses when a concurrent redemption spent the challenge first', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();
    const redeemLink = t.auth.context.tokens.redeemLink.bind(t.auth.context.tokens);

    Object.assign(t.auth.context.tokens, {
      redeemLink: async (purpose: string, token: unknown) => (
        await redeemLink(purpose, token),
        redeemLink(purpose, token)
      ),
    });

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(done).toMatchObject({ code: 'invalid_second_factor', reason: 'challenge_lost_race' });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'two_factor.failed',
      reason: 'challenge_lost_race',
    });
  });

  it('refuses when the user was deleted during the challenge', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();
    const { challenge } = await t.challenged();

    await t.stores.users.softDelete(userId);

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(done).toMatchObject({ code: 'invalid_second_factor', reason: 'user_missing' });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'two_factor.failed',
      userId,
      reason: 'user_missing',
    });
  });

  it('passes the session refusal of an app hook through', async () => {
    let refuseNow = false;

    const t = twoFactorApp(
      {},
      {
        hooks: {
          beforeSessionCreate: () =>
            refuseNow
              ? { refuse: true as const, code: 'forbidden' as const, reason: 'app_says_no' }
              : undefined,
        },
      },
    );

    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    refuseNow = true;

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(done).toMatchObject({ ok: false, code: 'forbidden', reason: 'app_says_no' });
  });

  it('rate limits code checks per IP', async () => {
    const t = twoFactorApp({ perIp: { limit: 2, window: '1m' } });

    const verify = () =>
      t.auth.twoFactor.verifyChallenge({
        challenge: unknownToken(),
        proof: { kind: 'totp', code: '000000' },
        meta: meta('198.51.100.9'),
      });

    await verify();
    await verify();

    const limited = await verify();

    expect(limited).toMatchObject({ ok: false, code: 'rate_limited' });
    expect(!limited.ok && limited.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('gives a required user without a factor an enrollment challenge that ends in a session', async () => {
    const t = twoFactorApp({ required: ({ user }) => user.email === EMAIL });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const { challenge } = await t.challenged();
    const started = await t.auth.twoFactor.enroll({ challenge, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const recovery = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'recovery-code', code: 'abcde-fghjk' },
      meta: meta(),
    });

    expect(!recovery.ok && recovery.reason).toBe('enrollment_required');

    const device = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'trusted-device', token: unknownToken() },
      meta: meta(),
    });

    expect(!device.ok && device.reason).toBe('enrollment_required');

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(started.value.secret) },
      meta: meta(),
    });

    if (!done.ok) throw new Error(done.reason);

    expect(done.value.recoveryCodes).toHaveLength(10);
    expect(await t.sessionOf(done.value.session.token)).not.toBeNull();
    expect((await t.store.findFactor(done.value.session.session.userId))?.confirmed).toBe(true);
  });

  it('refuses an enrollment challenge confirmed without enrolling first', async () => {
    const t = twoFactorApp({ required: () => true });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const { challenge } = await t.challenged();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: '123456' },
      meta: meta(),
    });

    expect(!done.ok && done.reason).toBe('no_pending_enrollment');
  });

  it('lets a user with neither a factor nor a requirement straight in', async () => {
    const t = twoFactorApp();

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind).toBe('session');
  });
});

describe('factor locks and the permanent lockout tier', () => {
  const permanent = { throttle: { lockout: { permanent: { afterLocks: 1 } } } };

  /** Six wrong codes on unknown challenges: one lock under the challenges' own keys. */
  async function lockUnknown(t: ReturnType<typeof twoFactorApp>) {
    const challenge = unknownToken();

    for (let i = 0; i < 6; i++) {
      await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'totp', code: '000000' },
        meta: meta(`198.51.100.${i}`),
      });
    }
  }

  it('counts nothing toward any account for the lock of an unknown challenge', async () => {
    const t = twoFactorApp({}, permanent);

    await t.enrolled();

    for (let round = 0; round < 3; round++) {
      await lockUnknown(t);
      t.clock.advance(60 * 60_000);
    }

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind).toBe('challenge');
    expect(t.mailer.sent.filter((m) => m.type === 'lockout')).toEqual([]);
  });

  it('leaves factor locks out of the count while the tier is off', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 6; i++) {
        const { challenge } = await t.challenged(EMAIL, { ip: `198.51.${round}.${i}` });

        await t.auth.twoFactor.verifyChallenge({
          challenge,
          proof: { kind: 'totp', code: t.codeFor(secret) === '000000' ? '111111' : '000000' },
          meta: meta(`198.51.${round}.${i}`),
        });
      }

      t.clock.advance(60 * 60_000);
    }

    expect((await t.auth.lockout.inspect({ email: EMAIL })).locked).toBe(false);
    expect((await t.passed(secret)).session.userId).toBeDefined();
  });
});

describe('trusted devices', () => {
  it('trusts a device on request and lets it skip the next challenge, without a step-up', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();
    const { challenge } = await t.challenged();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!done.ok) throw new Error(done.reason);

    const device = done.value.trustedDevice;

    expect(device?.token).toMatch(/^[0-9a-f]{64}$/u);
    expect(device?.expiresAt).toBe(t.clock.now() + 30 * 24 * 3600_000);

    expect(device?.cookie).toEqual({
      name: '__Host-two-factor-device',
      value: device?.token,
      attributes: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 30 * 24 * 3600,
      },
    });

    expect(t.auth.twoFactor.trustedDeviceCookieName).toBe('__Host-two-factor-device');

    expect(
      t.auth.twoFactor.readTrustedDeviceToken(`a=b; __Host-two-factor-device=${device?.token}`),
    ).toBe(device?.token);

    expect(t.auth.twoFactor.readTrustedDeviceToken(undefined)).toBeNull();

    const next = await t.challenged();

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge: next.challenge,
      proof: { kind: 'trusted-device', token: device?.token },
      meta: meta(),
    });

    if (!skipped.ok) throw new Error(skipped.reason);

    expect(skipped.value.session.session.userId).toBe(userId);
    expect(skipped.value.trustedDevice).toBeNull();

    const step = await t.auth.twoFactor.requireStepUp(skipped.value.session.session);

    expect(step).toMatchObject({ ok: false, code: 'second_factor_required' });
  });

  it('does not trust a second device off a device proof', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const first = await t.challenged();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: first.challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    const next = await t.challenged();

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge: next.challenge,
      proof: { kind: 'trusted-device', token: done.ok ? done.value.trustedDevice?.token : '' },
      rememberDevice: true,
      meta: meta(),
    });

    expect(skipped.ok && skipped.value.trustedDevice).toBeNull();
  });

  it('refuses an unknown, malformed, expired or foreign device token', async () => {
    const t = twoFactorApp({ trustedDevices: { ttl: '1d', maxPerUser: 2 } });
    const { secret } = await t.enrolled();
    const grace = await t.enrolled('grace@example.com');

    const graceDone = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged('grace@example.com')).challenge,
      proof: { kind: 'totp', code: t.codeFor(grace.secret) },
      rememberDevice: true,
      meta: meta(),
    });

    const adaDone = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!graceDone.ok || !adaDone.ok) throw new Error('setup');

    const tryToken = async (token: string | null | undefined) => {
      const { challenge } = await t.challenged();

      return t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'trusted-device', token },
        meta: meta(),
      });
    };

    for (const token of [
      unknownToken(),
      'nope',
      null,
      undefined,
      graceDone.value.trustedDevice?.token,
    ]) {
      expect(await tryToken(token)).toMatchObject({ ok: false, reason: 'device_not_trusted' });
    }

    expect((await tryToken(adaDone.value.trustedDevice?.token)).ok).toBe(true);
    t.clock.advance(24 * 3600_000);

    expect(await tryToken(adaDone.value.trustedDevice?.token)).toMatchObject({
      ok: false,
      reason: 'device_not_trusted',
    });
  });

  it('refuses a device proof when trusted devices are off, and trusts nothing new', async () => {
    const t = twoFactorApp({ trustedDevices: false });
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    expect(done.ok && done.value.trustedDevice).toBeNull();

    const next = await t.challenged();

    const device = await t.auth.twoFactor.verifyChallenge({
      challenge: next.challenge,
      proof: { kind: 'trusted-device', token: unknownToken() },
      meta: meta(),
    });

    expect(!device.ok && device.reason).toBe('device_not_trusted');
  });

  it('does not count a stale device cookie against the factor budget', async () => {
    const t = twoFactorApp({ attempts: { limit: 1, window: '15m' } });
    const { secret } = await t.enrolled();

    for (let i = 0; i < 3; i++) {
      const { challenge } = await t.challenged();

      await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'trusted-device', token: unknownToken() },
        meta: meta(),
      });
    }

    const { challenge } = await t.challenged();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(done.ok).toBe(true);
  });

  it('forgets every trusted device on request', async () => {
    const t = twoFactorApp();
    const { secret, session } = await t.enrolled();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    await t.auth.twoFactor.revokeTrustedDevices({ session, meta: meta() });

    const { challenge } = await t.challenged();

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'trusted-device', token: done.ok ? done.value.trustedDevice?.token : '' },
      meta: meta(),
    });

    expect(!skipped.ok && skipped.reason).toBe('device_not_trusted');
    expect(t.audit.types()).toContain('two_factor.trusted_devices_revoked');
  });

  it('keeps trusted devices when one session ends', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!done.ok) throw new Error(done.reason);

    await t.auth.logout({ token: done.value.session.token, meta: meta() });

    const { challenge } = await t.challenged();

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'trusted-device', token: done.value.trustedDevice?.token },
      meta: meta(),
    });

    expect(skipped.ok).toBe(true);
  });
});
