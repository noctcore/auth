// What the opt-in permanent lockout tier does beyond the password login: it
// ends the account's sessions, closes the doors a live session could use to
// get around it, follows the account through an email change, starts over
// after a successful sign-in, and does not pass from an address to a new
// account registered on it. Both `trustedDevices` modes.
import { describe, expect, it, vi } from 'vitest';

import type { LockoutOptions } from '../../src';
import type { NormalizedEmail } from '../../src/shared/email';
import { meta, NEW_PASSWORD, PASSWORD, settled, setup } from './setup';

const EMAIL = 'ada@example.com';
const MIN = 60_000;

const SMALL = {
  perAccount: { limit: 2, window: '15m' },
  perAccountIp: { limit: 100, window: '15m' },
} as const satisfies LockoutOptions;

type App = ReturnType<typeof setup>;

function app(lockout: LockoutOptions, onSessionsRevoked = vi.fn()) {
  return setup({ throttle: { lockout: { ...SMALL, ...lockout } }, hooks: { onSessionsRevoked } });
}

/** Three wrong passwords from fresh sources: one new lock. */
async function lockOnce(t: App, email = EMAIL) {
  for (let i = 0; i < 3; i++)
    await t.auth.login({ email, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

  await settled();
}

/** Two locks in a row with `afterLocks: 1`: the second is permanent. */
async function lockForGood(t: App, email = EMAIL) {
  await lockOnce(t, email);
  t.clock.advance(5 * MIN);
  await lockOnce(t, email);
}

async function signIn(t: App, options: { email?: string; deviceToken?: string } = {}) {
  const result = await t.auth.login({
    email: options.email ?? EMAIL,
    password: PASSWORD,
    meta: meta('198.51.100.20'),
    ...(options.deviceToken ? { deviceToken: options.deviceToken } : {}),
  });

  return result.ok && result.value.kind === 'session' ? result.value.session : null;
}

/** Registers `EMAIL` and signs in once: a session and a trusted-device cookie. */
async function owner(t: App) {
  await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
  await settled();

  const issued = await signIn(t);

  if (!issued) throw new Error('sign-in failed');

  return {
    token: issued.token,
    session: issued.session,
    deviceToken: issued.deviceCookie.value,
    userId: issued.session.userId,
  };
}

const alive = async (t: App, token: string) =>
  (await t.auth.validateRequest({ token, meta: meta() })).ok;

describe('permanent lock with trusted devices (the default)', () => {
  it('deletes every session but keeps device cookies, and tells onSessionsRevoked', async () => {
    const revoked = vi.fn();
    const t = app({ permanent: { afterLocks: 1 } }, revoked);
    const before = await owner(t);

    await lockForGood(t);
    await settled();

    expect(await alive(t, before.token)).toBe(false);

    expect(revoked).toHaveBeenCalledWith(
      expect.objectContaining({ userId: before.userId, reason: 'locked-permanently' }),
    );

    expect(await signIn(t, { deviceToken: before.deviceToken })).not.toBeNull();
  });

  it('lets a session from a device sign-in reauthenticate and change the password, never the email', async () => {
    const t = app({ permanent: { afterLocks: 1 } });
    const before = await owner(t);

    await lockForGood(t);
    await settled();

    const device = await signIn(t, { deviceToken: before.deviceToken });
    const session = device?.session ?? before.session;

    const reauthed = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    expect(reauthed.ok).toBe(true);

    const fresh = reauthed.ok ? reauthed.value.session : session;

    const change = await t.auth.requestEmailChange({
      session: fresh,
      newEmail: 'elsewhere@example.com',
      meta: meta(),
    });

    expect(!change.ok && change.reason).toBe('permanently_locked');
    expect(t.mailer.sent.filter((m) => m.type === 'email-change-confirm')).toHaveLength(0);

    const changed = await t.auth.changePassword({
      session: fresh,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(changed.ok).toBe(true);
  });
});

describe('an email change started before the permanent lock', () => {
  it('cannot be confirmed after it, by code, and the code is left unspent', async () => {
    const t = app({ permanent: { afterLocks: 1 } });
    const before = await owner(t);

    const requested = await t.auth.requestEmailChange({
      session: before.session,
      newEmail: 'elsewhere@example.com',
      meta: meta(),
    });

    expect(requested.ok).toBe(true);
    await settled();

    const code = t.mailer.last('email-change-confirm')?.code ?? '';

    await lockForGood(t);
    await settled();

    const device = await signIn(t, { deviceToken: before.deviceToken });
    const session = device?.session ?? before.session;
    const confirmed = await t.auth.confirmEmailChangeCode({ session, code, meta: meta() });

    expect(!confirmed.ok && confirmed.reason).toBe('permanently_locked');

    await t.auth.lockout.clear({ userId: before.userId, meta: meta() });
    expect((await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).ok).toBe(true);
  });
});

describe('permanent lock without trusted devices', () => {
  const strict = { permanent: { afterLocks: 1, trustedDevices: false } } as const;

  it('bumps the epoch: every session and device cookie ends', async () => {
    const revoked = vi.fn();
    const t = app(strict, revoked);
    const before = await owner(t);
    const epoch = await t.stores.sessions.getEpoch(before.userId);

    await lockForGood(t);
    await settled();

    expect(await alive(t, before.token)).toBe(false);
    expect(await t.stores.sessions.getEpoch(before.userId)).toBe(epoch + 1);
    expect(revoked).toHaveBeenCalledWith(expect.objectContaining({ reason: 'locked-permanently' }));
    expect(await signIn(t, { deviceToken: before.deviceToken })).toBeNull();
  });

  it('refuses every session door, and issuing a session by any path', async () => {
    const t = app(strict);
    const before = await owner(t);

    await lockForGood(t);
    await settled();

    // A session minted by a login that raced the lock, at the new epoch.
    const epoch = await t.stores.sessions.getEpoch(before.userId);
    const session = { ...before.session, epoch };

    await t.stores.sessions.create(session, 60 * MIN);

    const answers = [
      await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() }),
      await t.auth.changePassword({
        session,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
        meta: meta(),
      }),
      await t.auth.verifyEmailCode({ session, code: '00000000', meta: meta() }),
      await t.auth.verifyEmailLink({ token: 'not-a-token', session, meta: meta() }),
    ];

    expect(answers.map((a) => !a.ok && a.reason)).toEqual(Array(4).fill('permanently_locked'));

    const user = await t.stores.users.findById(before.userId);
    const sso = await t.auth.context.issueSession(user as never, { via: 'sso', meta: meta() });

    expect(!sso.ok && sso.reason).toBe('permanently_locked');

    await t.auth.lockout.clear({ userId: before.userId, meta: meta() });
    expect(await signIn(t)).not.toBeNull();
  });
});

describe('the permanent lock follows the account', () => {
  it('holds after the account moves to another address', async () => {
    const t = app({ permanent: { afterLocks: 1 } });
    const before = await owner(t);

    await lockForGood(t);

    const moved = await t.stores.users.changeEmail?.(before.userId, {
      from: EMAIL as NormalizedEmail,
      to: 'moved@example.com' as NormalizedEmail,
    });

    expect(moved).toBe('changed');

    const login = await t.auth.login({
      email: 'moved@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.30'),
    });

    expect(!login.ok && login.reason).toBe('permanently_locked');
    expect((await t.auth.lockout.inspect({ userId: before.userId })).permanent).toBe(true);
  });

  it('starts the count over after a successful sign-in', async () => {
    const t = app({ permanent: { afterLocks: 1 } });

    await owner(t);
    await lockOnce(t);
    t.clock.advance(5 * MIN);
    expect(await signIn(t)).not.toBeNull();

    await lockOnce(t);
    t.clock.advance(15 * MIN);

    expect(await signIn(t)).not.toBeNull();
    expect((await t.auth.lockout.inspect({ email: EMAIL })).permanent).toBe(false);
  });

  it('does not pass from an address with no account to the account registered on it', async () => {
    const t = app({ permanent: { afterLocks: 1 } });

    await lockForGood(t, 'ghost@example.com');
    expect((await t.auth.lockout.inspect({ email: 'ghost@example.com' })).permanent).toBe(true);

    await t.auth.register({ email: 'ghost@example.com', password: PASSWORD, meta: meta() });
    await settled();

    expect((await t.auth.lockout.inspect({ email: 'ghost@example.com' })).permanent).toBe(false);
    // The temporary lock is the address's own and still runs out on its own clock.
    t.clock.advance(60 * MIN);
    expect(await signIn(t, { email: 'ghost@example.com' })).not.toBeNull();
  });

  it("leaves an existing account's lock alone when someone signs up on its address", async () => {
    const t = app({ permanent: { afterLocks: 1 } });

    await owner(t);
    await lockForGood(t);
    await t.auth.register({ email: EMAIL, password: 'some other passphrase', meta: meta() });
    await settled();

    expect((await t.auth.lockout.inspect({ email: EMAIL })).permanent).toBe(true);
  });
});
