import { describe, expect, it } from 'vitest';

import { AuthConfigError, createAuth } from '../../src';
import { twoFactor } from '../../src/plugins/two-factor';
import {
  manualClock,
  memoryStores,
  MemoryTwoFactorStore,
  plainHasher,
  recordingMailer,
} from '../../src/testing';
import { EMAIL, meta, NEW_PASSWORD, PASSWORD, SECRET, testCipher, twoFactorApp } from './setup';

const OK = { ok: true, value: undefined };

describe('step-up', () => {
  it('records a proof for the session that lasts the step-up window, then lapses', async () => {
    const t = twoFactorApp({ stepUpWindow: '5m' });
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(5 * 60_000);

    expect(await t.auth.twoFactor.requireStepUp(session)).toMatchObject({
      ok: false,
      code: 'second_factor_required',
      reason: 'step_up_required',
    });

    const step = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(step).toEqual({ ok: true, value: { expiresAt: t.clock.now() + 5 * 60_000 } });

    expect(t.audit.events.find((e) => e.type === 'two_factor.step_up')?.data).toEqual({
      method: 'totp',
    });

    // Fresh authentication is checked first: the login was 5 minutes ago, still fresh.
    expect(await t.auth.twoFactor.requireStepUp(session)).toEqual(OK);
  });

  it('needs fresh authentication on top of the proof', async () => {
    const t = twoFactorApp({ stepUpWindow: '1h' });
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(11 * 60_000);

    expect(await t.auth.twoFactor.requireStepUp(session)).toMatchObject({
      ok: false,
      code: 'fresh_auth_required',
    });
  });

  it('lets a user without a factor pass on fresh authentication alone', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    expect(await t.auth.twoFactor.requireStepUp(session)).toEqual(OK);
  });

  it('refuses a wrong proof, and a proof stored for another user', async () => {
    const t = twoFactorApp();
    const { secret, session } = await t.enrolled();
    const passedSession = (await t.passed(secret)).session;

    const wrong = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: '000000' },
      meta: meta(),
    });

    expect(wrong).toMatchObject({ ok: false, code: 'invalid_second_factor' });

    await t.store.putStepUp({
      sessionId: passedSession.id,
      userId: 'someone-else',
      expiresAt: t.clock.now() + 60_000,
    });

    expect((await t.auth.twoFactor.requireStepUp(passedSession)).ok).toBe(false);
  });

  it('refuses a step-up proof of a user without a factor, by TOTP or by recovery code', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    for (const proof of [
      { kind: 'totp', code: '123456' },
      { kind: 'recovery-code', code: 'abcde-fghjk' },
    ] as const) {
      const step = await t.auth.twoFactor.stepUp({ session, proof, meta: meta() });

      expect(step).toMatchObject({ ok: false, code: 'invalid_second_factor', reason: 'no_factor' });
    }
  });

  it('rate limits step-up per IP', async () => {
    const t = twoFactorApp({ perIp: { limit: 0, window: '1m' } });
    const { session } = await t.signedIn();

    const step = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: '000000' },
      meta: meta(),
    });

    expect(!step.ok && step.code).toBe('rate_limited');
  });
});

describe('managing the factor', () => {
  it('reports the status', async () => {
    let requireGrace = false;

    const t = twoFactorApp({
      required: ({ user }) => requireGrace && user.email === 'grace@example.com',
    });

    const { session } = await t.signedIn();

    expect(await t.auth.twoFactor.status(session)).toEqual({
      ok: true,
      value: { enabled: false, pending: false, required: false, recoveryCodesRemaining: 0 },
    });

    await t.auth.twoFactor.enroll({ session, meta: meta() });

    expect(
      (await t.auth.twoFactor.status(session)).ok && (await t.auth.twoFactor.status(session)),
    ).toMatchObject({
      value: { enabled: false, pending: true },
    });

    const grace = await t.enrolled('grace@example.com');

    requireGrace = true;

    expect(await t.auth.twoFactor.status(grace.session)).toEqual({
      ok: true,
      value: { enabled: true, pending: false, required: true, recoveryCodesRemaining: 10 },
    });

    await t.stores.users.softDelete(session.userId);

    expect(await t.auth.twoFactor.status(session)).toMatchObject({
      ok: false,
      code: 'session_expired',
    });
  });

  it('turns the factor off with a step-up, deleting codes and devices and mailing the owner', async () => {
    const t = twoFactorApp();
    const { secret, session, userId } = await t.enrolled();

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!done.ok) throw new Error(done.reason);

    const off = await t.auth.twoFactor.disable({
      session: done.value.session.session,
      meta: meta(),
    });

    expect(off).toEqual({ ok: true, value: { disabled: true } });
    expect(await t.store.findFactor(userId)).toBeNull();
    expect(await t.store.countRecoveryCodes(userId)).toBe(0);
    expect(await t.store.findTrustedDevice(userId, '')).toBeNull();
    await Promise.resolve();
    expect(t.mailer.last('two-factor-disabled')).toMatchObject({ to: EMAIL, userId });
    expect(t.audit.types()).toContain('two_factor.disabled');

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind).toBe('session');

    expect(await t.auth.twoFactor.disable({ session, meta: meta() })).toEqual({
      ok: true,
      value: { disabled: false },
    });
  });

  it('drops a pending enrollment without a mail', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    await t.auth.twoFactor.enroll({ session, meta: meta() });

    expect(await t.auth.twoFactor.disable({ session, meta: meta() })).toEqual({
      ok: true,
      value: { disabled: false },
    });

    expect(await t.store.findFactor(session.userId)).toBeNull();
    await Promise.resolve();
    expect(t.mailer.last('two-factor-disabled')).toBeUndefined();
  });

  it('refuses to turn a required factor off, even with a step-up', async () => {
    const t = twoFactorApp({ required: () => true });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const { challenge } = await t.challenged();
    const started = await t.auth.twoFactor.enroll({ challenge, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(started.value.secret) },
      meta: meta(),
    });

    if (!done.ok) throw new Error(done.reason);

    const off = await t.auth.twoFactor.disable({
      session: done.value.session.session,
      meta: meta(),
    });

    expect(off).toMatchObject({ ok: false, code: 'forbidden', reason: 'factor_required' });
  });

  it('answers session_expired for a missing user', async () => {
    const t = twoFactorApp();
    const { session } = await t.enrolled();

    await t.stores.users.softDelete(session.userId);

    expect(await t.auth.twoFactor.disable({ session, meta: meta() })).toMatchObject({
      ok: false,
      code: 'session_expired',
    });
  });

  it('regenerates recovery codes with a step-up, voiding the old set', async () => {
    const t = twoFactorApp();
    const { session, recoveryCodes, userId, secret } = await t.enrolled();
    const regenerated = await t.auth.twoFactor.regenerateRecoveryCodes({ session, meta: meta() });

    if (!regenerated.ok) throw new Error(regenerated.reason);

    expect(regenerated.value.recoveryCodes).toHaveLength(10);
    expect(regenerated.value.recoveryCodes).not.toContain(recoveryCodes[0]);
    expect(await t.store.countRecoveryCodes(userId)).toBe(10);

    const { challenge } = await t.challenged();

    const old = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'recovery-code', code: recoveryCodes[0] ?? '' },
      meta: meta(),
    });

    expect(!old.ok && old.reason).toBe('wrong_recovery_code');

    const fresh = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'recovery-code', code: regenerated.value.recoveryCodes[0] ?? '' },
      meta: meta(),
    });

    expect(fresh.ok).toBe(true);
    expect(secret).toBeTruthy();
  });

  it('refuses to regenerate without a factor or without a step-up', async () => {
    const t = twoFactorApp();
    const plain = await t.signedIn('grace@example.com');

    expect(
      await t.auth.twoFactor.regenerateRecoveryCodes({ session: plain.session, meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'forbidden',
      reason: 'no_factor',
    });

    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(10 * 60_000);

    expect(await t.auth.twoFactor.regenerateRecoveryCodes({ session, meta: meta() })).toMatchObject(
      {
        ok: false,
        code: 'fresh_auth_required',
      },
    );
  });
});

describe('the core flows with a factor on', () => {
  it('changes the password with a step-up in the session', async () => {
    const t = twoFactorApp();
    const { session } = await t.enrolled();

    const changed = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(changed.ok).toBe(true);
  });

  it('changes the password with a code instead, and refuses without either', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(10 * 60_000);

    const change = (secondFactor?: string) =>
      t.auth.changePassword({
        session,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
        ...(secondFactor === undefined ? {} : { secondFactor }),
        meta: meta(),
      });

    expect(await change()).toMatchObject({ ok: false, code: 'second_factor_required' });
    expect(await change('000000')).toMatchObject({ ok: false, code: 'invalid_second_factor' });
    expect((await change(t.codeFor(secret))).ok).toBe(true);
  });

  it('changes the password of a user without a factor as before', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    const changed = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(changed.ok).toBe(true);
  });

  it('resets the password only with a code or a recovery code, and keeps the factor', async () => {
    const t = twoFactorApp();
    const { secret, recoveryCodes, userId } = await t.enrolled();

    const linkFor = async () => {
      await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
      await new Promise((resolve) => setTimeout(resolve, 0));

      return (t.mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';
    };

    const reset = (token: string, secondFactor?: string) =>
      t.auth.resetPassword({
        token,
        password: NEW_PASSWORD,
        ...(secondFactor === undefined ? {} : { secondFactor }),
        meta: meta(),
      });

    const token = await linkFor();

    expect(await reset(token)).toMatchObject({ ok: false, code: 'second_factor_required' });

    expect(await reset(token, '000000')).toMatchObject({
      ok: false,
      code: 'invalid_second_factor',
    });

    expect((await reset(token, t.codeFor(secret))).ok).toBe(true);
    expect((await t.store.findFactor(userId))?.confirmed).toBe(true);

    expect(
      t.audit.events.find(
        (e) => e.type === 'two_factor.verified' && e.data?.['action'] === 'reset',
      ),
    ).toBeTruthy();

    t.nextStep();

    const second = await linkFor();

    expect((await reset(second, recoveryCodes[1])).ok).toBe(true);
  });

  it('rate limits the code checks of a reset per IP', async () => {
    // Enrollment spends two hits (start and confirm); the reset's check is the third.
    const t = twoFactorApp({ perIp: { limit: 2, window: '1m' } });

    await t.enrolled();
    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const token = (t.mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';

    const reset = await t.auth.resetPassword({
      token,
      password: NEW_PASSWORD,
      secondFactor: '123456',
      meta: meta(),
    });

    expect(!reset.ok && reset.code).toBe('rate_limited');
  });
});

describe('configuration', () => {
  const store = new MemoryTwoFactorStore();
  const { cipher } = testCipher();

  it('checks the options at creation', () => {
    const make = (options: Record<string, unknown>) => () =>
      twoFactor({ store, cipher, issuer: 'Acme', ...options } as Parameters<typeof twoFactor>[0]);

    expect(make({})).not.toThrow();
    expect(make({ store: undefined })).toThrow(/store is required/u);
    expect(make({ cipher: undefined })).toThrow(/cipher is required/u);
    expect(make({ issuer: '' })).toThrow(/issuer is required/u);
    expect(make({ issuer: 7 })).toThrow(/issuer is required/u);
    expect(make({ issuer: 'Acme: Inc' })).toThrow(/colon/u);
    expect(make({ stepUpWindow: 0 })).toThrow(/stepUpWindow/u);
    expect(make({ trustedDevices: { ttl: 0 } })).toThrow(/ttl/u);
    expect(make({ trustedDevices: { maxPerUser: 0 } })).toThrow(/maxPerUser/u);
    expect(make({ trustedDevices: { maxPerUser: 1.5 } })).toThrow(/maxPerUser/u);
    expect(make({ trustedDevices: { maxPerUser: 1 } })).not.toThrow();
  });

  it('belongs to one createAuth', () => {
    const plugin = twoFactor({ store, cipher, issuer: 'Acme' });

    const config = {
      stores: memoryStores(),
      password: { hasher: plainHasher() },
      secret: SECRET,
      urls: { resetPassword: (token: string) => token },
      mailer: recordingMailer(),
      clock: manualClock(),
      plugins: [plugin],
    };

    createAuth(config);
    expect(() => createAuth(config)).toThrow(AuthConfigError);
  });

  it('refuses to run a hook before createAuth bound it', async () => {
    const plugin = twoFactor({ store, cipher, issuer: 'Acme' });
    const hook = plugin.hooks?.onSessionsRevoked as (context: object) => Promise<void>;

    await expect(hook({ userId: 'u', sessionIds: [], reason: 'revoke-all' })).rejects.toThrow(
      /createAuth/u,
    );
  });

  it('tries the stand-in secret again after the cipher failed once', async () => {
    const t = twoFactorApp();
    const encrypt = t.cipher.encrypt.bind(t.cipher);
    let failures = 1;

    t.cipher.encrypt = async (secret, context) => {
      if (failures-- > 0) throw new Error('kms down');

      return encrypt(secret, context);
    };

    const verify = () =>
      t.auth.twoFactor.verifyChallenge({
        challenge: 'f'.repeat(64),
        proof: { kind: 'totp', code: '123456' },
        meta: meta(),
      });

    await expect(verify()).rejects.toThrow(/kms down/u);
    expect(await verify()).toMatchObject({ ok: false, reason: 'challenge_unknown' });
    expect(await verify()).toMatchObject({ ok: false, reason: 'challenge_unknown' });
  });
});
