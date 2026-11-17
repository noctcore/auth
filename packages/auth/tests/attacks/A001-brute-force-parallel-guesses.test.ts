// A001: brute force by parallel guesses.
//
// An attacker fires many password guesses at one account at once, hoping the
// checks race and let more guesses through than the budget allows.
//
// Stopped by: throttle/throttle.ts: gateLogin reserves an attempt (an atomic increment)
//   before the password is verified, per (account, IP), per account, and per device.
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import { accountKey } from '../../src/throttle/counter-keys';
import { EMAIL, meta, PASSWORD, registered } from './support';

describe('A001: brute force by parallel guesses', () => {
  it('lets no more than the account-wide budget of a parallel burst from many IPs reach a verdict', async () => {
    const { auth } = await registered();

    const burst = await Promise.all(
      Array.from({ length: 60 }, (_, i) =>
        auth.login({
          email: EMAIL,
          password: `guess number ${String(i).padStart(3, '0')}`,
          meta: meta(`198.18.${i}.1`),
        }),
      ),
    );

    expect(burst.filter((r) => !r.ok && r.reason === 'wrong_password')).toHaveLength(10);
    expect(burst.every((r) => !r.ok && r.code === 'invalid_credentials')).toBe(true);

    // The budget is spent: even the right password is now refused.
    const owner = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('198.18.250.1'),
    });

    expect(!owner.ok && owner.reason).toBe('locked');
  });

  it('lets no more than five guesses from one IP reach a verdict, however many arrive at once', async () => {
    const { auth } = await registered();

    const burst = await Promise.all(
      Array.from({ length: 40 }, (_, i) =>
        auth.login({
          email: EMAIL,
          password: `guess number ${String(i).padStart(3, '0')}`,
          meta: meta('192.0.2.66'),
        }),
      ),
    );

    const reasons = burst.map((r) => !r.ok && r.reason);

    expect(reasons.filter((r) => r === 'wrong_password')).toHaveLength(5);

    // The rest are refused before any verdict: by the per-(account, IP) budget
    // or, past ten a minute, by the login door's own per-IP limit.
    expect(
      reasons.filter((r) => r === 'account_ip_budget' || r === 'rate_limited:login'),
    ).toHaveLength(35);
  });

  it('gives four cookies firing twenty wrong guesses each at once five password checks in all', async () => {
    const { auth, stores } = await registered();
    const tokens: string[] = [];

    for (let i = 0; i < 4; i++) {
      const r = await auth.login({
        email: EMAIL,
        password: PASSWORD,
        meta: meta(`203.0.113.${i}`),
      });

      if (!r.ok || r.value.kind !== 'session') throw new Error('login failed');

      tokens.push(r.value.session.deviceCookie.value);
    }

    for (let i = 0; i < 11; i++)
      await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

    const account = accountKey(EMAIL as never);

    // A correct login under the lock refunds both device counters.
    const owner = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      deviceToken: tokens[0] ?? null,
      meta: meta('203.0.113.50'),
    });

    if (!owner.ok || owner.value.kind !== 'session')
      throw new Error('owner refused under the lock');

    expect((await stores.counters.get(`devs:${account}`))?.count).toBe(0);

    const burst = await Promise.all(
      Array.from({ length: 80 }, (_, i) =>
        auth.login({
          email: EMAIL,
          password: `wrong guess ${String(i).padStart(3, '0')}!`,
          deviceToken: tokens[i % 4] ?? null,
          meta: meta(`198.18.${i}.1`),
        }),
      ),
    );

    expect(burst.filter((r) => !r.ok && r.reason === 'wrong_password')).toHaveLength(5);
    expect(burst.filter((r) => !r.ok && r.reason === 'device_budget')).toHaveLength(75);
  });
});
