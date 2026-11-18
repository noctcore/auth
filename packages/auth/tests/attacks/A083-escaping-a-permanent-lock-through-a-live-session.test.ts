// A083: escaping a permanent lock through a live session.
//
// The permanent tier refuses the password login. An attacker who holds a
// session the lock did not end (one opened earlier, or minted by a login
// racing the lock) tries to reauthenticate, move the account to an address
// with no lock on it, and sign in there.
//
// Stopped by: flows/permanent-lock.ts (the lock ends every session; no
//   session may change the email; without trusted devices every session
//   door and every session issue is refused), throttle/throttle.ts (the
//   marker is keyed on the user id, so it follows the account to any
//   address), flows/lock-notice.ts (runs the revocation when the lock lands).
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import type { LockoutOptions } from '../../src';
import type { NormalizedEmail } from '../../src/shared/email';
import { EMAIL, meta, PASSWORD, settled, setup } from './support';

const MIN = 60_000;

const SMALL = {
  perAccount: { limit: 2, window: '15m' },
  perAccountIp: { limit: 100, window: '15m' },
} as const satisfies LockoutOptions;

type App = ReturnType<typeof setup>;

async function signedIn(lockout: LockoutOptions) {
  const t = setup({ throttle: { lockout: { ...SMALL, ...lockout } } });

  await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
  await settled();

  const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

  if (!login.ok || login.value.kind !== 'session') throw new Error('sign-in failed');

  return { t, held: login.value.session };
}

async function lockForGood(t: App) {
  for (let round = 0; round < 2; round++) {
    for (let i = 0; i < 3; i++)
      await t.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });

    t.clock.advance(5 * MIN);
  }

  await settled();
}

describe('A083: escaping a permanent lock through a live session', () => {
  for (const trustedDevices of [true, false]) {
    it(`loses the session it held when the lock lands (trustedDevices: ${String(trustedDevices)})`, async () => {
      const { t, held } = await signedIn({ permanent: { afterLocks: 1, trustedDevices } });

      await lockForGood(t);

      expect((await t.auth.validateRequest({ token: held.token, meta: meta() })).ok).toBe(false);

      const reauth = await t.auth.reauthenticate({
        session: held.session,
        password: PASSWORD,
        meta: meta(),
      });

      expect(reauth.ok).toBe(false);
    });
  }

  it('cannot move the account to an unlocked address, even from a session that raced the lock', async () => {
    const { t, held } = await signedIn({ permanent: { afterLocks: 1 } });

    await lockForGood(t);

    // A session minted by a login that got past the gate just before the marker.
    const raced = { ...held.session, id: `${held.session.id}-raced` };

    await t.stores.sessions.create(raced, 60 * MIN);

    const change = await t.auth.requestEmailChange({
      session: raced,
      newEmail: 'unlocked@example.com',
      meta: meta(),
    });

    expect(!change.ok && change.reason).toBe('permanently_locked');
  });

  it('finds the lock waiting at the new address when the account moves anyway', async () => {
    const { t, held } = await signedIn({ permanent: { afterLocks: 1 } });

    await lockForGood(t);

    // An admin tool or a direct store write moves the address; the lock goes along.
    await t.stores.users.changeEmail?.(held.session.userId, {
      from: EMAIL as NormalizedEmail,
      to: 'unlocked@example.com' as NormalizedEmail,
    });

    const login = await t.auth.login({
      email: 'unlocked@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.40'),
    });

    expect(!login.ok && login.reason).toBe('permanently_locked');
  });
});
