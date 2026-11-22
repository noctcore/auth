// A102: guessing the password through a stolen session.
//
// An attacker holds a session cookie that is alive but not fresh. Login is
// locked, so they guess the password through the doors that prove it from a
// session instead: `reauthenticate` and `changePassword`. Each door had its
// own looser budget and never read the lock, so together they checked about
// 30 guesses per 15 minutes while login checked none, and a right guess
// returned a fresh session (and the password).
//
// Stopped by: flows/password-change.ts (both doors reserve an attempt in
//   login's budgets before the verify: per (account, IP) and account-wide,
//   and under a lock the trusted devices' shared budget, the live session
//   standing in for a device), throttle/throttle.ts (`gateLogin`).
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import { toPublicError } from '../../src';
import { EMAIL, meta, NEW_PASSWORD, PASSWORD, settled, setup } from './support';

const WRONG = 'wrong passphrase!';
const MIN = 60_000;

async function signedIn() {
  const t = setup();

  await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
  await settled();

  const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

  if (!login.ok || login.value.kind !== 'session') throw new Error('sign-in failed');

  return { t, session: login.value.session.session };
}

describe('A102: guessing the password through a stolen session', () => {
  it('checks no more guesses through both doors in 15 minutes than login would', async () => {
    const { t, session } = await signedIn();

    // Lock the account through login.
    for (let i = 0; i < 11; i++)
      await t.auth.login({ email: EMAIL, password: WRONG, meta: meta(`192.0.2.${i}`) });

    let checked = 0;
    const attacker = meta('198.51.100.66');

    // One guess through each door every minute: inside each door's own limit.
    for (let minute = 0; minute < 15; minute++) {
      const reauth = await t.auth.reauthenticate({ session, password: WRONG, meta: attacker });

      const change = await t.auth.changePassword({
        session,
        currentPassword: WRONG,
        newPassword: NEW_PASSWORD,
        meta: attacker,
      });

      for (const result of [reauth, change])
        if (!result.ok && result.reason === 'wrong_password') checked++;

      t.clock.advance(MIN);
    }

    // A trusted device gets 5 per 15 minutes at a locked login; a fresh
    // per (account, IP) budget of 5 opens when the lock lapses.
    expect(checked).toBeLessThanOrEqual(10);
  });

  it('refuses the right password once the budget is spent, the way login refuses it', async () => {
    const { t, session } = await signedIn();

    for (let i = 0; i < 11; i++)
      await t.auth.login({ email: EMAIL, password: WRONG, meta: meta(`192.0.2.${i}`) });

    // Five wrong guesses over both doors, inside each door's own limit.
    for (let i = 0; i < 3; i++)
      await t.auth.reauthenticate({ session, password: WRONG, meta: meta('198.51.100.66') });

    for (let i = 0; i < 2; i++)
      await t.auth.changePassword({
        session,
        currentPassword: WRONG,
        newPassword: NEW_PASSWORD,
        meta: meta('198.51.100.66'),
      });

    const right = await t.auth.reauthenticate({
      session,
      password: PASSWORD,
      meta: meta('198.51.100.66'),
    });

    expect(!right.ok && right.reason).toBe('device_budget');
    expect(!right.ok && toPublicError(right)).toEqual({ code: 'invalid_credentials' });
  });
});
