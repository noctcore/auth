// A005: the locked-account oracle.
//
// An attacker locks an address on purpose and watches for a "locked" answer or a
// lockout mail: if only real accounts lock, the lock reveals the account.
//
// Stopped by: throttle/throttle.ts (counters keyed on the address, so unknown addresses lock
//   too), flows/login.ts (a locked account answers invalid_credentials after the
//   same work), flows/lock-notice.ts (mail only to a real owner, off the response path).
// Learn: Enumeration (/auth/learn/enumeration/), Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import { toPublicError } from '../../src';
import { EMAIL, meta, PASSWORD, registered, setup } from './support';

describe('A005: the locked-account oracle', () => {
  it('locks the account after 10 failures from many sources, mails the owner once and answers like a wrong password', async () => {
    const { auth, mailer, clock } = await registered();

    for (let i = 0; i < 11; i++)
      await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

    expect(mailer.sent.filter((m) => m.type === 'lockout')).toHaveLength(1);

    const locked = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('198.51.100.20'),
    });

    expect(!locked.ok && locked.reason).toBe('locked');
    expect(!locked.ok && toPublicError(locked)).toEqual({ code: 'invalid_credentials' });
    clock.advance(5 * 60_000);

    expect(
      (await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('198.51.100.20') })).ok,
    ).toBe(true);
  });

  it('does the same lockout work for an unknown address (no existence oracle)', async () => {
    const { auth, mailer } = setup();

    for (let i = 0; i < 11; i++)
      await auth.login({
        email: 'ghost@example.com',
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });

    const after = await auth.login({
      email: 'ghost@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.20'),
    });

    expect(!after.ok && after.reason).toBe('locked');
    expect(mailer.sent.filter((m) => m.type === 'lockout')).toHaveLength(0);
  });
});
