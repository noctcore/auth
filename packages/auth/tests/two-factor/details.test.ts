// The details the attack and flow tests do not pin: the audit rows each
// refusal writes, the data a challenge carries, the keys the limits count
// under, and the edges of the input parsing.
import { describe, expect, it } from 'vitest';

import { NO_SUCH_USER_ID } from '../../src';
import { sha256Hex } from '../../src/crypto/hash';
import { normalizeRecoveryCode } from '../../src/plugins/two-factor/recovery-codes';
import { twoFactor } from '../../src/plugins/two-factor';
import { MemoryTwoFactorStore } from '../../src/testing';
import { setup } from '../flows/setup';
import {
  EMAIL,
  meta,
  NEW_PASSWORD,
  PASSWORD,
  testCipher,
  twoFactorApp,
  unknownToken,
  type TwoFactorApp,
} from './setup';

const last = (t: TwoFactorApp) => t.audit.events.at(-1);
const wrongCode = (right: string) => (right === '000000' ? '111111' : '000000');

async function resetToken(t: TwoFactorApp) {
  await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
  await new Promise((resolve) => setTimeout(resolve, 0));

  return (t.mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';
}

describe('the challenge token', () => {
  it('carries the epoch, remember-me, the client tag and the mode, under its own purpose', async () => {
    const t = twoFactorApp({ required: ({ user }) => user.email === 'grace@example.com' });
    const ada = await t.enrolled();

    await t.auth.login({ email: EMAIL, password: PASSWORD, rememberMe: true, meta: meta() });

    expect((await t.stores.tokens.findByUser('two-factor-challenge', ada.userId))?.data).toEqual({
      epoch: '0',
      rememberMe: 'yes',
      client: sha256Hex('client:vitest'),
      mode: 'verify',
    });

    await t.auth.register({ email: 'grace@example.com', password: PASSWORD, meta: meta() });
    await t.challenged('grace@example.com');

    const grace = await t.stores.users.findCredentialByEmail('grace@example.com' as never);

    expect(
      (await t.stores.tokens.findByUser('two-factor-challenge', grace?.id ?? ''))?.data,
    ).toMatchObject({
      rememberMe: 'no',
      mode: 'enroll',
    });
  });

  it('carries remember-me into the session it ends in, and its absence', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    expect((await t.passed(secret)).session.rememberMe).toBe(false);
  });

  it('spends no factor budget of the user on an expired challenge', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    t.clock.advance(5 * 60_000);

    for (let i = 0; i < 5; i++)
      await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'totp', code: '000000' },
        meta: meta(),
      });

    expect(last(t)).toMatchObject({ type: 'two_factor.failed', reason: 'challenge_expired' });
    expect(last(t)).not.toHaveProperty('userId');

    expect(
      (
        await t.auth.twoFactor.verifyChallenge({
          challenge: (await t.challenged()).challenge,
          proof: { kind: 'totp', code: t.codeFor(secret) },
          meta: meta(),
        })
      ).ok,
    ).toBe(true);
  });
});

describe('audit rows', () => {
  it('writes a failed row with the user for a wrong code, without one for an unknown challenge', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();

    await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: wrongCode(t.codeFor(secret)) },
      meta: meta(),
    });

    expect(last(t)).toMatchObject({ type: 'two_factor.failed', userId, reason: 'wrong_code' });

    await t.auth.twoFactor.verifyChallenge({
      challenge: unknownToken(),
      proof: { kind: 'totp', code: '123456' },
      meta: meta(),
    });

    expect(last(t)).toEqual(
      expect.objectContaining({ type: 'two_factor.failed', reason: 'challenge_unknown' }),
    );

    expect(last(t)).not.toHaveProperty('userId');
  });

  it('writes the step-up failure, the trusted device and the rate limit', async () => {
    const t = twoFactorApp({ perIp: { limit: 2, window: '1m' } });
    const { secret, session, userId } = await t.enrolled();

    await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: wrongCode(t.codeFor(secret)) },
      meta: meta('198.51.100.1'),
    });

    expect(last(t)).toMatchObject({ type: 'two_factor.failed', userId, reason: 'wrong_code' });

    await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta('198.51.100.2'),
    });

    expect(t.audit.events).toContainEqual(
      expect.objectContaining({ type: 'two_factor.trusted_device_added', userId }),
    );

    const ip = meta('198.51.100.3');

    await t.auth.twoFactor.stepUp({ session, proof: { kind: 'totp', code: '000000' }, meta: ip });
    await t.auth.twoFactor.stepUp({ session, proof: { kind: 'totp', code: '000000' }, meta: ip });

    const limited = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: '000000' },
      meta: ip,
    });

    expect(limited).toMatchObject({
      ok: false,
      code: 'rate_limited',
      reason: 'rate_limited:two-factor',
    });

    expect(last(t)).toMatchObject({ type: 'rate_limit.exceeded', reason: 'two-factor' });

    // Another address has a window of its own.
    const other = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: '000000' },
      meta: meta('198.51.100.4'),
    });

    expect(!other.ok && other.code).toBe('invalid_second_factor');
  });

  it('writes the enrollment refusals', async () => {
    const t = twoFactorApp();
    const { session, userId, secret } = await t.enrolled();
    const encrypts = t.cipherCalls.encrypt;

    expect(await t.auth.twoFactor.enroll({ session, meta: meta() })).toMatchObject({
      code: 'forbidden',
      reason: 'factor_active',
    });

    expect(t.cipherCalls.encrypt).toBe(encrypts);
    expect(last(t)).toMatchObject({ type: 'two_factor.refused', userId, reason: 'factor_active' });

    // A verify-mode challenge is no enrollment challenge.
    const { challenge } = await t.challenged();

    expect(await t.auth.twoFactor.enroll({ challenge, meta: meta() })).toMatchObject({
      code: 'invalid_token',
      reason: 'enroll_challenge',
    });

    expect(last(t)).toMatchObject({
      type: 'two_factor.failed',
      userId,
      reason: 'enroll_challenge',
    });

    await t.auth.twoFactor.enroll({ challenge: unknownToken(), meta: meta() });
    expect(last(t)).toMatchObject({ type: 'two_factor.failed', reason: 'enroll_challenge' });
    expect(last(t)).not.toHaveProperty('userId');

    const grace = await t.signedIn('grace@example.com');
    const started = await t.auth.twoFactor.enroll({ session: grace.session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    await t.auth.twoFactor.confirmEnrollment({
      session: grace.session,
      code: wrongCode(t.codeFor(started.value.secret)),
      meta: meta(),
    });

    expect(last(t)).toMatchObject({
      type: 'two_factor.failed',
      userId: grace.session.userId,
      reason: 'wrong_code',
    });

    expect(secret).toBeTruthy();
  });

  it('answers user_missing for a session whose user is gone, in every flow that looks the user up', async () => {
    const t = twoFactorApp();
    const { session, userId } = await t.enrolled();
    const grace = await t.signedIn('grace@example.com');

    await t.stores.users.softDelete(userId);
    await t.stores.users.softDelete(grace.session.userId);

    expect(await t.auth.twoFactor.disable({ session, meta: meta() })).toMatchObject({
      code: 'session_expired',
      reason: 'user_missing',
    });

    expect(await t.auth.twoFactor.status(session)).toMatchObject({
      code: 'session_expired',
      reason: 'user_missing',
    });

    expect(await t.auth.twoFactor.enroll({ session: grace.session, meta: meta() })).toMatchObject({
      code: 'session_expired',
      reason: 'user_missing',
    });
  });

  it('re-issues the session on confirmation with revokeOtherSessions, revoking the rest under its own reason', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      revokeOtherSessions: true,
      meta: meta(),
    });

    expect(t.audit.events).toContainEqual(
      expect.objectContaining({ type: 'sessions.revoked', reason: 'two-factor-enabled' }),
    );
  });

  it('answers user_missing when the user is gone before the re-issue', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const findById = t.stores.users.findById.bind(t.stores.users);
    let calls = 0;

    // The confirmation looks the user up once for its mail; the re-issue is the second lookup.
    t.stores.users.findById = async (id) => (++calls >= 2 ? null : findById(id));

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      revokeOtherSessions: true,
      meta: meta(),
    });

    expect(confirmed).toMatchObject({ code: 'session_expired', reason: 'user_missing' });
  });

  it('writes the management refusals', async () => {
    let required = false;
    const t = twoFactorApp({ required: ({ user }) => required && user.email === EMAIL });
    const { session, userId } = await t.enrolled();

    required = true;

    expect(await t.auth.twoFactor.disable({ session, meta: meta() })).toMatchObject({
      code: 'forbidden',
      reason: 'factor_required',
    });

    expect(last(t)).toMatchObject({
      type: 'two_factor.refused',
      userId,
      reason: 'factor_required',
    });

    const grace = await t.signedIn('grace@example.com');

    expect(
      await t.auth.twoFactor.regenerateRecoveryCodes({ session: grace.session, meta: meta() }),
    ).toMatchObject({
      code: 'forbidden',
      reason: 'no_factor',
    });

    expect(last(t)).toMatchObject({
      type: 'two_factor.refused',
      userId: grace.session.userId,
      reason: 'no_factor',
    });

    t.clock.advance(10 * 60_000);

    const fresh = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!fresh.ok) throw new Error(fresh.reason);

    await t.auth.twoFactor.regenerateRecoveryCodes({ session: fresh.value.session, meta: meta() });

    expect(last(t)).toMatchObject({
      type: 'two_factor.refused',
      userId,
      reason: 'step_up_required',
    });
  });

  it('writes the step-up refusal of turning a factor off', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    t.clock.advance(10 * 60_000);

    const fresh = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!fresh.ok) throw new Error(fresh.reason);

    await t.auth.twoFactor.disable({ session: fresh.value.session, meta: meta() });

    expect(last(t)).toMatchObject({
      type: 'two_factor.refused',
      userId,
      reason: 'step_up_required',
    });
  });
});

describe('the core hooks', () => {
  it('names the action and the reason in reset and password change refusals', async () => {
    const t = twoFactorApp();
    const { secret, session } = await t.enrolled();
    const token = await resetToken(t);

    expect(
      await t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta() }),
    ).toMatchObject({
      code: 'second_factor_required',
      reason: 'reset_reset_second_factor_missing',
    });

    t.clock.advance(10 * 60_000);

    const fresh = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!fresh.ok) throw new Error(fresh.reason);

    const changed = await t.auth.changePassword({
      session: fresh.value.session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      secondFactor: wrongCode(t.codeFor(secret)),
      meta: meta(),
    });

    expect(changed).toMatchObject({
      code: 'invalid_second_factor',
      reason: 'password_change_second_factor_wrong_code',
    });
  });

  it('reads six digits, spaces allowed, as a TOTP code and anything else as a recovery code', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const token = await resetToken(t);

    const reset = (secondFactor: string) =>
      t.auth.resetPassword({ token, password: NEW_PASSWORD, secondFactor, meta: meta() });

    for (const odd of ['1234567', 'a123456', '123456a'])
      expect(await reset(odd)).toMatchObject({
        reason: 'reset_reset_second_factor_malformed_recovery_code',
      });

    const code = t.codeFor(secret);

    expect((await reset(` ${code.slice(0, 3)} ${code.slice(3)} `)).ok).toBe(true);
  });

  it('lets the session re-issued by an email verification through', async () => {
    const t = twoFactorApp({}, { emailVerification: { kind: 'code' } });
    const { session } = await t.enrolled();

    await t.auth.requestEmailVerification({ session, meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const code = t.mailer.last('verify-email')?.code ?? '';
    const verified = await t.auth.verifyEmailCode({ session, code, meta: meta() });

    expect(verified.ok).toBe(true);
  });

  it('keeps trusted devices through a logout and the revocation of one session', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();

    const passed = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!passed.ok || !passed.value.trustedDevice) throw new Error('no device');

    const device = await t.store.findTrustedDevice(
      userId,
      sha256Hex(passed.value.trustedDevice.token),
    );

    t.nextStep();

    const other = await t.passed(secret);

    await t.auth.sessions.revoke({
      session: passed.value.session.session,
      handle: t.auth.sessions.handle(other.session.id),
      meta: meta(),
    });

    await t.auth.logout({ token: passed.value.session.token, meta: meta() });

    expect(
      await t.store.findTrustedDevice(userId, sha256Hex(passed.value.trustedDevice.token)),
    ).toEqual(device);
  });

  it('keeps trusted devices for the revocations of single sessions only', async () => {
    const t = twoFactorApp();
    const { userId } = await t.enrolled();
    const hash = sha256Hex(unknownToken());

    const add = () =>
      t.store.addTrustedDevice(
        { userId, hash, epoch: 0, createdAt: t.clock.now(), expiresAt: t.clock.now() + 60_000 },
        5,
      );

    await add();

    for (const reason of ['logout', 'revoke-one', 'evicted']) {
      await t.auth.context.notifyRevoked(userId, [], reason);
      expect(await t.store.findTrustedDevice(userId, hash)).not.toBeNull();
    }

    await t.auth.context.notifyRevoked(userId, [], 'password-change');
    expect(await t.store.findTrustedDevice(userId, hash)).toBeNull();
  });

  it('writes the refusal of an enrollment that lost a race with another one', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    t.store.putPendingFactor = async () => false;

    expect(await t.auth.twoFactor.enroll({ session, meta: meta() })).toMatchObject({
      code: 'forbidden',
      reason: 'factor_active',
    });

    expect(last(t)).toMatchObject({ type: 'two_factor.refused', reason: 'factor_active' });
  });

  it('looks a device up under no user for an unknown challenge, and refuses', async () => {
    const t = twoFactorApp();

    await t.enrolled();

    const finds: string[] = [];
    const find = t.store.findTrustedDevice.bind(t.store);

    t.store.findTrustedDevice = async (userId, hash) => (finds.push(userId), find(userId, hash));

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge: unknownToken(),
      proof: { kind: 'trusted-device', token: unknownToken() },
      meta: meta(),
    });

    expect(!skipped.ok && skipped.reason).toBe('challenge_unknown');
    expect(finds).toEqual([NO_SUCH_USER_ID]);
  });

  it('refuses a stored device once trusted devices are off', async () => {
    const t = twoFactorApp({ trustedDevices: false });
    const { userId } = await t.enrolled();
    const token = unknownToken();

    await t.store.addTrustedDevice(
      {
        userId,
        hash: sha256Hex(token),
        epoch: 0,
        createdAt: t.clock.now(),
        expiresAt: t.clock.now() + 60_000,
      },
      5,
    );

    const skipped = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'trusted-device', token },
      meta: meta(),
    });

    expect(!skipped.ok && skipped.reason).toBe('device_not_trusted');
  });
});

describe('limits and stored forms', () => {
  it("locks one user's factor without touching another's", async () => {
    const t = twoFactorApp();
    const ada = await t.enrolled();
    const grace = await t.enrolled('grace@example.com');

    for (let i = 0; i < 6; i++)
      await t.auth.twoFactor.stepUp({
        session: ada.session,
        proof: { kind: 'totp', code: wrongCode(t.codeFor(ada.secret)) },
        meta: meta(),
      });

    const step = await t.auth.twoFactor.stepUp({
      session: grace.session,
      proof: { kind: 'totp', code: t.codeFor(grace.secret) },
      meta: meta('198.51.100.9'),
    });

    expect(step.ok).toBe(true);
  });

  it('spends no recovery code on a challenge from another client', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, userId } = await t.enrolled();
    const { challenge } = await t.challenged();

    const stolen = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'recovery-code', code: recoveryCodes[0] ?? '' },
      meta: { ...meta(), userAgent: 'attacker' },
    });

    expect(!stolen.ok && stolen.reason).toBe('client_mismatch');
    expect(await t.store.countRecoveryCodes(userId)).toBe(10);
  });

  it('stores each recovery code as the keyed hash of user and code, under its own purpose', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, userId } = await t.enrolled();

    const hash = t.auth.context.keyedHash(
      'two-factor-recovery-code',
      `${userId}:${(recoveryCodes[0] ?? '').replace('-', '')}`,
    );

    expect(await t.store.consumeRecoveryCode(userId, hash)).toBe(true);
  });

  it('accepts a typed recovery code up to 32 characters, separators included', () => {
    expect(normalizeRecoveryCode(`abcde-fghjk${' '.repeat(21)}`)).toBe('abcdefghjk');
    expect(normalizeRecoveryCode(`abcde-fghjk${' '.repeat(22)}`)).toBeNull();
    expect(normalizeRecoveryCode('0abcde-fghjk')).toBeNull();
    expect(normalizeRecoveryCode('abcde-fghjk0')).toBeNull();
  });

  it('names the reason when one plugin instance goes to a second createAuth', () => {
    const plugin = twoFactor({
      store: new MemoryTwoFactorStore(),
      cipher: testCipher().cipher,
      issuer: 'Acme',
    });

    setup({ plugins: [plugin] });

    expect(() => setup({ plugins: [plugin] })).toThrow(
      'twoFactor: one plugin instance per createAuth',
    );
  });
});
