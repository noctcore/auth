// A108: never reaching the permanent lockout tier while guessing the second
// factor with the password in hand.
//
// With `lockout.permanent` on, an attacker who knows the password guesses
// TOTP codes. Before each round they sign in with the password, which used to
// start the count of locks in a row over, then spend the factor's budget until
// it locks, wait the lock out and go again: about five guesses an hour,
// forever, and the factor's own locks never counted toward the tier anyway.
// The same reset came from a correct password at a step-up door
// (`reauthenticate`), which proves no second factor.
//
// Stopped by: core/auth-core.ts (`issueSession`: only a completed sign-in,
//   `via: 'password'` or `via: 'second-factor'` without `inherit`, starts the
//   count over, through `Throttle.signInCompleted`), throttle/throttle.ts
//   (`loginSucceeded` hands back the source's budget and nothing else;
//   `escalate` counts a factor's new lock in the same count as the password
//   locks), plugins/two-factor/runtime.ts (`gateAttempt` passes each new
//   factor lock to `context.escalateLock`, which carries a permanent lock out
//   like a password one).
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/), Second factors (/auth/learn/second-factors/)
import { describe, expect, it, vi } from 'vitest';

import type { LockoutOptions } from '../../src';
import { meta, PASSWORD, settled, setup } from './support';
import { EMAIL, twoFactorApp, type TwoFactorApp } from '../two-factor/setup';

const MIN = 60_000;

const wrong = (code: string) => (code === '000000' ? '111111' : '000000');

/** Small password budgets: three wrong passwords from fresh sources set one lock. */
const SMALL = {
  perAccount: { limit: 2, window: '15m' },
  perAccountIp: { limit: 100, window: '15m' },
} as const satisfies LockoutOptions;

/**
 * One round of the attack: the password, then a wrong code, six times over
 * (a challenge takes five codes, so each guess starts a new one), from six
 * IPs. The sixth wrong code crosses the factor's budget of five and locks it.
 */
async function guessRound(t: TwoFactorApp, secret: string, round: number) {
  for (let i = 0; i < 6; i++) {
    const ip = `198.51.${round}.${i}`;
    const { challenge } = await t.challenged(EMAIL, { ip });

    const guess = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: wrong(t.codeFor(secret)) },
      meta: meta(ip),
    });

    expect(guess.ok).toBe(false);
  }

  await settled();
}

type Login = { readonly auth: Pick<ReturnType<typeof setup>['auth'], 'login'> };

/** Three wrong passwords from fresh sources: one new password lock. */
async function lockOnce(t: Login) {
  for (let i = 0; i < 3; i++)
    await t.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

  await settled();
}

describe('A108: climbing past the permanent tier on second-factor codes', () => {
  it('reaches the permanent lock on the fourth factor lock, though every round starts with the right password', async () => {
    const revoked = vi.fn();

    const t = twoFactorApp(
      {},
      {
        throttle: { lockout: { permanent: { afterLocks: 3 } } },
        hooks: { onSessionsRevoked: revoked },
      },
    );

    const { secret, token } = await t.enrolled();

    for (let round = 0; round < 4; round++) {
      await guessRound(t, secret, round);
      // Past the longest factor lock (the backoff is capped at `maxLock`, 1 h).
      t.clock.advance(60 * MIN);
    }

    // The password alone no longer opens even a challenge, from anywhere.
    const login = await t.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('192.0.2.99'),
    });

    expect(login).toMatchObject({ ok: false, reason: 'permanently_locked' });
    expect((await t.auth.lockout.inspect({ email: EMAIL })).permanent).toBe(true);

    // Carried out like a permanent password lock: one notice, the sessions end.
    const notices = t.mailer.sent.filter((m) => m.type === 'lockout');

    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ permanent: true });
    expect(t.audit.events.filter((e) => e.type === 'account.locked_permanently')).toHaveLength(1);
    expect(revoked).toHaveBeenCalledWith(expect.objectContaining({ reason: 'locked-permanently' }));
    expect((await t.auth.validateRequest({ token, meta: meta() })).ok).toBe(false);
  });

  it('does not start the count over on a correct password that opens a challenge', async () => {
    const t = twoFactorApp(
      {},
      { throttle: { lockout: { ...SMALL, permanent: { afterLocks: 1 } } } },
    );

    await t.enrolled();
    await lockOnce(t);
    t.clock.advance(5 * MIN);

    // The attacker's password is right; the second factor is still owed.
    await t.challenged(EMAIL, { ip: '198.51.100.40' });

    await lockOnce(t);

    expect((await t.auth.lockout.inspect({ email: EMAIL })).permanent).toBe(true);
  });

  it('still starts the count over on a completed sign-in, the second factor passed', async () => {
    const t = twoFactorApp(
      {},
      { throttle: { lockout: { ...SMALL, permanent: { afterLocks: 1 } } } },
    );

    const { secret } = await t.enrolled();

    await lockOnce(t);
    t.clock.advance(5 * MIN);
    await t.passed(secret);

    await lockOnce(t);

    expect((await t.auth.lockout.inspect({ email: EMAIL })).permanent).toBe(false);
  });

  it('does not start the count over on a correct password at reauthenticate', async () => {
    const t = setup({ throttle: { lockout: { ...SMALL, permanent: { afterLocks: 1 } } } });
    const { session } = await t.signedInUser(EMAIL);

    await lockOnce(t);
    t.clock.advance(5 * MIN);

    const reauthed = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    expect(reauthed.ok).toBe(true);

    await lockOnce(t);

    expect((await t.auth.lockout.inspect({ email: EMAIL })).permanent).toBe(true);
  });
});
