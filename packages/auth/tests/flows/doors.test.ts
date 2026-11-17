// Every door's rate limit and captcha refusal, and the races where an account
// disappears or a write is refused between a check and the write it guards.
import { describe, expect, it } from 'vitest';

import type { PasswordResetJob } from '../../src';
import type { StoredSession } from '../../src/ports/stores';
import { meta, NEW_PASSWORD, PASSWORD, setup } from './setup';

const EMAIL = 'ada@example.com';
const ONE = { limit: 1, window: '1m' } as const;
const tokenOf = (url: string | undefined) => (url ?? '').split('#')[1] ?? '';

const rejectingCaptcha = {
  verify: async (token: string | undefined): Promise<'pass' | 'reject'> =>
    token === 'good' ? 'pass' : 'reject',
};

describe('door rate limits', () => {
  it('refuses the second login from one IP within the window', async () => {
    const { auth, signedInUser } = setup({
      throttle: { doors: { login: { limit: 2, window: '1m' } } },
    });

    await signedInUser(EMAIL);
    await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    const limited = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(!limited.ok && limited.code).toBe('rate_limited');
    expect(!limited.ok && limited.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('refuses a second reset request, code guess and reset from one IP', async () => {
    const jobs: PasswordResetJob[] = [];

    const { auth } = setup({
      throttle: {
        doors: { 'password-reset-request': ONE, 'password-reset-code': ONE, 'password-reset': ONE },
      },
      passwordReset: { kind: 'code', enqueue: async (job) => void jobs.push(job) },
    });

    await auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await auth.verifyPasswordResetCode({ email: EMAIL, code: '00000000', meta: meta() });
    await auth.resetPassword({ token: 'x'.repeat(64), password: NEW_PASSWORD, meta: meta() });

    const request = await auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    const code = await auth.verifyPasswordResetCode({ email: EMAIL, code: '0000', meta: meta() });

    const reset = await auth.resetPassword({
      token: 'x'.repeat(64),
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect([request, code, reset].map((r) => !r.ok && r.code)).toEqual([
      'rate_limited',
      'rate_limited',
      'rate_limited',
    ]);
  });

  it('refuses a second password change by the same user', async () => {
    const { auth, signedInUser } = setup({ throttle: { doors: { 'password-change': ONE } } });
    const { session } = await signedInUser(EMAIL);

    await auth.changePassword({
      session,
      currentPassword: 'wrong passphrase!',
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    const limited = await auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!limited.ok && limited.code).toBe('rate_limited');
  });
});

describe('captcha on login and reset request', () => {
  it('refuses a missing or failed captcha before any account work, and audits the login', async () => {
    const { auth, audit, stores } = setup({ captcha: rejectingCaptcha });
    const before = await stores.users.findCredentialByEmail(EMAIL as never);
    const login = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });
    const reset = await auth.requestPasswordReset({ email: EMAIL, meta: meta() });

    expect(before).toBeNull();
    expect(!login.ok && login.code).toBe('captcha_failed');
    expect(!reset.ok && reset.code).toBe('captcha_failed');
    expect(audit.events.filter((e) => e.type === 'login.failure')).toHaveLength(1);
  });

  it('refuses a malformed address on the reset request', async () => {
    const { auth } = setup();
    const result = await auth.requestPasswordReset({ email: 'not-an-email', meta: meta() });

    expect(!result.ok && result.code).toBe('invalid_email');
  });
});

describe('login edges', () => {
  it('answers an account without a password like a wrong password', async () => {
    const { auth, stores, signedInUser } = setup();
    const { session } = await signedInUser(EMAIL);

    await stores.users.clearPassword(session.userId);

    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result).toMatchObject({
      ok: false,
      code: 'invalid_credentials',
      reason: 'password_not_set',
    });
  });

  it('passes over a challenge hook that declines and issues the session', async () => {
    const { auth, signedInUser } = setup({ hooks: { loginChallenge: async () => null } });

    await signedInUser(EMAIL);

    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result.ok && result.value.kind).toBe('session');
  });
});

describe('races between the check and the write', () => {
  it('ends a live session whose account vanished before a password change or sign out of other devices', async () => {
    const { auth, signedInUser, stores } = setup();
    const { session } = await signedInUser(EMAIL);

    await stores.users.softDelete(session.userId);

    const changed = await auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    const others = await auth.sessions.revokeOthers({ session, meta: meta() });

    for (const result of [changed, others])
      expect(result).toMatchObject({ ok: false, code: 'session_expired', reason: 'user_missing' });
  });

  it('ends the session when the account vanished before a password change', async () => {
    const { auth, signedInUser } = setup();
    const { session } = await signedInUser(EMAIL);
    const ghost = { ...session, userId: 'no-such-user' } as StoredSession<Record<string, never>>;

    const result = await auth.changePassword({
      session: ghost,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    // A session object naming another user is not a live session of that user.
    expect(result).toMatchObject({
      ok: false,
      code: 'session_expired',
      reason: 'session_not_active',
    });
  });

  it('ends the session when the password write is refused during a change', async () => {
    const { auth, signedInUser, stores } = setup();
    const { session } = await signedInUser(EMAIL);

    stores.users.setPasswordHash = async () => false;

    const result = await auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(result).toMatchObject({ ok: false, code: 'session_expired', reason: 'user_missing' });
  });

  it('refuses a reset link whose account vanished, or whose write is refused', async () => {
    const jobs: PasswordResetJob[] = [];

    const { auth, signedInUser, stores, mailer } = setup({
      passwordReset: { enqueue: async (job) => void jobs.push(job) },
    });

    await signedInUser(EMAIL);

    const linkFor = async () => {
      await auth.requestPasswordReset({ email: EMAIL, meta: meta() });

      for (const job of jobs.splice(0)) await auth.jobs.processPasswordReset(job);

      return tokenOf(mailer.last('password-reset')?.url);
    };

    const realFindById = stores.users.findById.bind(stores.users);
    const refusedWrite = await linkFor();

    stores.users.setPasswordHash = async () => false;

    const write = await auth.resetPassword({
      token: refusedWrite,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    const vanished = await linkFor();

    stores.users.findById = async () => null;

    const gone = await auth.resetPassword({
      token: vanished,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    stores.users.findById = realFindById;

    expect(write).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'reset_write_refused',
    });

    expect(gone).toMatchObject({ ok: false, code: 'invalid_token', reason: 'reset_user_missing' });
  });
});
