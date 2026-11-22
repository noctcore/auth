// A110: winning back the account-wide lockout budget without a completed
// sign-in, with `lockout.countSuccesses: false`.
//
// With successes not counted, a correct password's account-wide slot comes
// back. If it came back as soon as the password proved right, an attacker who
// holds the password but not the second factor could start challenge after
// challenge for free, and an outsider guessing passwords could have the
// owner's sign-ins (or any completion, repeated) wipe out the guesses already
// counted against the account.
//
// Stopped by: throttle/throttle.ts (`loginSucceeded` only records a slot as
//   owed, in a counter that lapses with the account-wide window;
//   `refundSuccess` hands one back per completion, never more than are owed,
//   claiming each refund atomically), core/auth-core.ts (`issueSession`: only
//   a completed sign-in, `via: 'password'` or `via: 'second-factor'` without
//   `inherit`, calls `Throttle.signInCompleted`).
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import type { LockoutOptions } from '../../src';
import { manualClock, MemoryCounterStore } from '../../src/testing';
import { accountKey } from '../../src/throttle/counter-keys';
import { Throttle } from '../../src/throttle/throttle';
import { meta, PASSWORD } from './support';
import { EMAIL, twoFactorApp } from '../two-factor/setup';

/** Three attempts from fresh sources in a window lock the account. */
const SMALL = {
  perAccount: { limit: 2, window: '15m' },
  perAccountIp: { limit: 100, window: '15m' },
  countSuccesses: false,
} as const satisfies LockoutOptions;

describe('A110: winning back the lockout budget without a completed sign-in', () => {
  it('spends a slot for every challenge the password opens until the factor is proved', async () => {
    const t = twoFactorApp({}, { throttle: { lockout: SMALL } });

    await t.enrolled();

    const answers = [];

    for (let i = 0; i < 3; i++) {
      const login = await t.auth.login({
        email: EMAIL,
        password: PASSWORD,
        meta: meta(`198.51.100.${i}`),
      });

      answers.push(login.ok ? login.value.kind : login.reason);
    }

    expect(answers).toEqual(['challenge', 'challenge', 'locked']);
  });

  it('never erases counted guesses with more completions than correct passwords', async () => {
    const clock = manualClock();
    const counters = new MemoryCounterStore(clock);
    const throttle = new Throttle(counters, clock, SMALL);
    const victim = accountKey('victim@example.com');

    // The owner proves the password once; an outsider guesses once.
    await throttle.gateLogin(victim, 'owner');
    await throttle.loginSucceeded(victim, 'owner');
    await throttle.gateLogin(victim, 'guess-1');

    // Completions, many and in parallel: one slot was owed, one comes back.
    await Promise.all(Array.from({ length: 20 }, () => throttle.signInCompleted(victim)));

    // The guess still counts: one more fits the budget, the next locks.
    expect((await throttle.gateLogin(victim, 'guess-2')).allowed).toBe(true);

    expect(await throttle.gateLogin(victim, 'guess-3')).toMatchObject({
      allowed: false,
      reason: 'locked',
    });
  });
});
