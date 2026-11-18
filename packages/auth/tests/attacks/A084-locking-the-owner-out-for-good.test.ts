// A084: locking the owner out for good through the permanent lockout tier.
//
// An attacker who knows an address fails on purpose from many IPs, lock after
// lock, so a permanent tier locks the owner out until an admin steps in, or
// hopes a password reset (which they might trigger) lifts it for them.
//
// Stopped by: throttle/throttle.ts (the tier is opt-in, off by default; the
//   owner's trusted device still gets through unless `trustedDevices` is
//   false; a reset never lifts it), flows/lockout-admin.ts (only an admin
//   clears it), flows/lock-notice.ts (the owner is mailed and the
//   onPermanentLock hook can alert support).
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import type { LockoutOptions } from '../../src';
import { EMAIL, meta, PASSWORD, registered, settled } from './support';

const MIN = 60_000;

type Env = Awaited<ReturnType<typeof registered>>;

/** The attacker's round: 11 wrong passwords from fresh IPs spend the account budget. */
async function attackRound(t: Env, round: number) {
  for (let i = 0; i < 11; i++) {
    await t.auth.login({
      email: EMAIL,
      password: 'wrong passphrase!',
      meta: meta(`192.0.${round}.${i}`),
    });
  }

  await settled();
}

const app = (lockout: LockoutOptions = {}) => registered({ throttle: { lockout } });

describe('A084: locking the owner out for good', () => {
  it('cannot lock anyone out for good by default: a day of rounds, and the lock still lapses', async () => {
    const t = await app();

    for (let round = 0; round < 24; round++) {
      await attackRound(t, round);
      t.clock.advance(60 * MIN);
    }

    expect((await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() })).ok).toBe(true);
  });

  it('with the tier on, still lets the owner in on a trusted device while strangers stay out', async () => {
    const t = await app({ permanent: { afterLocks: 2 } });
    const first = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    const deviceToken =
      first.ok && first.value.kind === 'session' ? first.value.session.deviceCookie.value : '';

    for (let round = 0; round < 3; round++) {
      await attackRound(t, round);
      t.clock.advance(60 * MIN);
    }

    const stranger = await t.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('198.51.100.20'),
    });

    expect(!stranger.ok && stranger.reason).toBe('permanently_locked');

    const owner = await t.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta(),
      deviceToken,
    });

    expect(owner.ok).toBe(true);
    expect(t.mailer.sent.filter((m) => m.type === 'lockout' && m.permanent)).toHaveLength(1);
  });

  it('cannot be lifted by a password reset or by waiting, only by an admin', async () => {
    const t = await app({ permanent: { afterLocks: 1 }, revealLocked: true });

    for (let round = 0; round < 2; round++) {
      await attackRound(t, round);
      t.clock.advance(60 * MIN);
    }

    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await settled();

    const token = (t.mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';
    const newPassword = 'a brand new passphrase';

    expect((await t.auth.resetPassword({ token, password: newPassword, meta: meta() })).ok).toBe(
      true,
    );

    t.clock.advance(90 * 24 * 60 * MIN);

    const login = () => t.auth.login({ email: EMAIL, password: newPassword, meta: meta() });
    const refused = await login();

    expect(!refused.ok && refused.code).toBe('account_locked');

    await t.auth.lockout.clear({ email: EMAIL, meta: meta() });
    expect((await login()).ok).toBe(true);
  });
});
