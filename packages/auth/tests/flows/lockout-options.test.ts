// The two opt-in lockout options: the permanent tier an admin clears
// (`throttle.lockout.permanent`) and the explicit `account_locked` answer
// (`throttle.lockout.revealLocked`). Both off by default.
import { describe, expect, it, vi } from 'vitest';

import { AuthConfigError, toPublicError, type LockoutOptions } from '../../src';
import { meta, PASSWORD, settled, setup } from './setup';

const EMAIL = 'ada@example.com';
const MIN = 60_000;

/** Two failures per account per window, so three lock it; sources never run out. */
const SMALL = {
  perAccount: { limit: 2, window: '15m' },
  perAccountIp: { limit: 100, window: '15m' },
} as const satisfies LockoutOptions;

type Env = ReturnType<typeof setup>;

async function registered(
  lockout: LockoutOptions,
  hooks?: NonNullable<Parameters<typeof setup>[0]>['hooks'],
) {
  const env = setup({
    throttle: { lockout: { ...SMALL, ...lockout } },
    ...(hooks ? { hooks } : {}),
  });

  await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
  await settled();

  return env;
}

/** Three wrong passwords from fresh sources: one new lock. */
async function lockOnce(env: Env, email = EMAIL) {
  for (let i = 0; i < 3; i++)
    await env.auth.login({ email, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

  await settled();
}

const signIn = (env: Env, extra: { deviceToken?: string; email?: string } = {}) =>
  env.auth.login({
    email: extra.email ?? EMAIL,
    password: PASSWORD,
    meta: meta('198.51.100.20'),
    ...(extra.deviceToken ? { deviceToken: extra.deviceToken } : {}),
  });

describe('permanent lockout tier', () => {
  it('is off by default: every lock lapses, however many in a row', async () => {
    const env = await registered({});

    for (let round = 0; round < 6; round++) {
      await lockOnce(env);
      env.clock.advance(60 * MIN);
    }

    expect((await signIn(env)).ok).toBe(true);

    expect(await env.auth.lockout.inspect({ email: EMAIL })).toEqual({
      locked: false,
      permanent: false,
      until: null,
    });
  });

  it('makes the lock after `afterLocks` temporary ones permanent, with a hook, an audit row and a mail', async () => {
    const onPermanentLock = vi.fn();
    const env = await registered({ permanent: { afterLocks: 2 } }, { onPermanentLock });

    await lockOnce(env);
    env.clock.advance(5 * MIN);
    await lockOnce(env);
    env.clock.advance(15 * MIN);
    expect((await signIn(env)).ok).toBe(true);
    expect(onPermanentLock).not.toHaveBeenCalled();

    await lockOnce(env);
    env.clock.advance(365 * 24 * 60 * MIN);

    const refused = await signIn(env);

    expect(!refused.ok && refused.reason).toBe('permanently_locked');
    expect(!refused.ok && toPublicError(refused)).toEqual({ code: 'invalid_credentials' });

    const user = await env.stores.users.findCredentialByEmail(EMAIL as never);

    expect(onPermanentLock).toHaveBeenCalledTimes(1);

    expect(onPermanentLock).toHaveBeenCalledWith(
      expect.objectContaining({ userId: user?.id, email: EMAIL }),
    );

    const mails = env.mailer.sent.filter((m) => m.type === 'lockout');

    expect(mails.map((m) => m.type === 'lockout' && m.permanent)).toEqual([
      undefined,
      undefined,
      true,
    ]);

    expect(env.audit.events.filter((e) => e.type === 'account.locked_permanently')).toHaveLength(1);
  });

  it('never decays the permanent tier, and a password reset does not lift it', async () => {
    const env = await registered({ permanent: { afterLocks: 1 } });

    await lockOnce(env);
    env.clock.advance(5 * MIN);
    await lockOnce(env);
    // The temporary lock lapses and so does the backoff tier; the permanent one holds.
    env.clock.advance(48 * 60 * MIN);

    await env.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await settled();

    const url = env.mailer.last('password-reset')?.url ?? '';

    const reset = await env.auth.resetPassword({
      token: url.split('#')[1] ?? '',
      password: 'a brand new passphrase',
      meta: meta(),
    });

    expect(reset.ok).toBe(true);

    const login = await env.auth.login({
      email: EMAIL,
      password: 'a brand new passphrase',
      meta: meta('198.51.100.20'),
    });

    expect(!login.ok && login.reason).toBe('permanently_locked');
  });

  it("lets the owner's trusted device through by default, and not with `trustedDevices: false`", async () => {
    for (const trustedDevices of [undefined, false] as const) {
      const env = await registered({
        permanent:
          trustedDevices === undefined ? { afterLocks: 1 } : { afterLocks: 1, trustedDevices },
      });

      const first = await signIn(env);

      const deviceToken =
        first.ok && first.value.kind === 'session' ? first.value.session.deviceCookie.value : '';

      await lockOnce(env);
      env.clock.advance(5 * MIN);
      await lockOnce(env);

      expect((await signIn(env)).ok).toBe(false);
      expect((await signIn(env, { deviceToken })).ok).toBe(trustedDevices === undefined);
    }
  });

  it('locks an unknown address for good too, without a hook or a mail', async () => {
    const onPermanentLock = vi.fn();
    const env = await registered({ permanent: { afterLocks: 1 } }, { onPermanentLock });
    const ghost = 'ghost@example.com';

    await lockOnce(env, ghost);
    env.clock.advance(5 * MIN);
    await lockOnce(env, ghost);

    const login = await signIn(env, { email: ghost });

    expect(!login.ok && login.reason).toBe('permanently_locked');
    expect(onPermanentLock).not.toHaveBeenCalled();
    expect(env.mailer.sent.filter((m) => m.type === 'lockout')).toHaveLength(0);
    expect((await env.auth.lockout.inspect({ email: ghost })).permanent).toBe(true);
  });

  it('logs a failing hook and still locks', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };

    const app = setup({
      throttle: { lockout: { ...SMALL, permanent: { afterLocks: 1 } } },
      logger,
      hooks: {
        onPermanentLock: () => {
          throw new Error('pager down');
        },
      },
    });

    await app.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    await settled();
    await lockOnce(app);
    app.clock.advance(5 * MIN);
    await lockOnce(app);

    expect((await signIn(app)).ok).toBe(false);
    expect(logger.error).toHaveBeenCalledWith('onPermanentLock hook failed', expect.anything());
  });

  it('refuses an `afterLocks` below 1 or not a whole number', () => {
    for (const afterLocks of [0, -1, 1.5, Number.NaN])
      expect(() => setup({ throttle: { lockout: { permanent: { afterLocks } } } })).toThrow(
        AuthConfigError,
      );
  });
});

describe('admin lockout tools', () => {
  it('inspects and clears a permanent lock by address or by user id', async () => {
    const env = await registered({ permanent: { afterLocks: 1 } });
    const user = await env.stores.users.findCredentialByEmail(EMAIL as never);
    const userId = user?.id ?? '';

    await lockOnce(env);
    env.clock.advance(5 * MIN);
    await lockOnce(env);
    env.clock.advance(60 * MIN);

    const held = { locked: true, permanent: true, until: null };

    expect(await env.auth.lockout.inspect({ email: ' Ada@Example.com ' })).toEqual(held);
    expect(await env.auth.lockout.inspect({ userId })).toEqual(held);
    expect(await env.auth.lockout.clear({ userId, meta: meta() })).toEqual(held);

    expect(env.audit.events.filter((e) => e.type === 'account.lock_cleared')).toEqual([
      expect.objectContaining({ userId, data: { permanent: true } }),
    ]);

    expect(await env.auth.lockout.inspect({ userId })).toEqual({
      locked: false,
      permanent: false,
      until: null,
    });

    expect((await signIn(env)).ok).toBe(true);
  });

  it('reports a temporary lock with its end, and clears it with its backoff', async () => {
    const env = await registered({});

    await lockOnce(env);

    const until = new Date(env.clock.now() + 5 * MIN);

    expect(await env.auth.lockout.inspect({ email: EMAIL })).toEqual({
      locked: true,
      permanent: false,
      until,
    });

    await env.auth.lockout.clear({ email: EMAIL, meta: meta() });
    expect((await signIn(env)).ok).toBe(true);

    // The backoff started over: the next lock is the first tier again.
    await lockOnce(env);

    expect((await env.auth.lockout.inspect({ email: EMAIL })).until).toEqual(
      new Date(env.clock.now() + 5 * MIN),
    );
  });

  it('answers unlocked, and audits nothing, for an unknown user, a bad address or no lock', async () => {
    const env = await registered({});
    const unlocked = { locked: false, permanent: false, until: null };

    expect(await env.auth.lockout.inspect({ userId: 'nobody' })).toEqual(unlocked);
    expect(await env.auth.lockout.inspect({ email: 'not an address' })).toEqual(unlocked);
    expect(await env.auth.lockout.clear({ userId: 'nobody', meta: meta() })).toEqual(unlocked);
    expect(await env.auth.lockout.clear({ email: EMAIL, meta: meta() })).toEqual(unlocked);
    expect(env.audit.events.filter((e) => e.type === 'account.lock_cleared')).toHaveLength(0);
  });
});

describe('explicit account_locked answer', () => {
  it('is off by default: a locked account answers invalid_credentials', async () => {
    const env = await registered({});

    await lockOnce(env);

    const login = await signIn(env);

    expect(!login.ok && toPublicError(login)).toEqual({ code: 'invalid_credentials' });
  });

  it('answers account_locked with the time left for a temporary lock', async () => {
    const env = await registered({ revealLocked: true });

    for (let i = 0; i < 2; i++)
      await env.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });

    const crossing = await env.auth.login({
      email: EMAIL,
      password: 'wrong passphrase!',
      meta: meta('192.0.2.9'),
    });

    expect(!crossing.ok && toPublicError(crossing)).toEqual({
      code: 'account_locked',
      retryAfterSeconds: 300,
    });

    env.clock.advance(MIN);

    const login = await signIn(env);

    expect(!login.ok && toPublicError(login)).toEqual({
      code: 'account_locked',
      retryAfterSeconds: 240,
    });

    env.clock.advance(4 * MIN);
    expect((await signIn(env)).ok).toBe(true);
  });

  it('answers account_locked with no retry time for a permanent lock', async () => {
    const env = await registered({ revealLocked: true, permanent: { afterLocks: 1 } });

    await lockOnce(env);
    env.clock.advance(5 * MIN);
    await lockOnce(env);

    const login = await signIn(env);

    expect(!login.ok && toPublicError(login)).toEqual({ code: 'account_locked' });
  });

  it("keeps a wrong password and one source's spent budget on invalid_credentials", async () => {
    const env = await registered({ revealLocked: true, perAccountIp: { limit: 1, window: '15m' } });

    const wrong = await env.auth.login({
      email: EMAIL,
      password: 'wrong passphrase!',
      meta: meta('192.0.2.1'),
    });

    const spent = await env.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('192.0.2.1'),
    });

    expect(!wrong.ok && toPublicError(wrong)).toEqual({ code: 'invalid_credentials' });
    expect(!spent.ok && spent.reason).toBe('account_ip_budget');
    expect(!spent.ok && toPublicError(spent)).toEqual({ code: 'invalid_credentials' });
  });

  it('answers account_locked for a trusted device that spent its budget under a lock', async () => {
    const env = await registered({ revealLocked: true, perDevice: { limit: 1, window: '15m' } });
    const first = await signIn(env);

    const deviceToken =
      first.ok && first.value.kind === 'session' ? first.value.session.deviceCookie.value : '';

    await lockOnce(env);

    await env.auth.login({
      email: EMAIL,
      password: 'wrong passphrase!',
      meta: meta(),
      deviceToken,
    });

    const login = await signIn(env, { deviceToken });

    expect(!login.ok && login.reason).toBe('device_budget');
    expect(!login.ok && toPublicError(login).code).toBe('account_locked');
  });
});
