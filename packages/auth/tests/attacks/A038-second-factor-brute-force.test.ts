// A038: brute forcing the second factor from many IPs.
//
// An attacker with the password guesses the 6-digit code (one in a million per
// guess, three per window with drift). Per-IP limits do not help against a
// botnet, and a counter checked after the comparison lets a parallel burst
// overrun it.
//
// Stopped by: throttle/throttle.ts (`gateFactor`: the attempt is reserved per account,
//   across every IP, BEFORE the comparison; 5 wrong codes lock the factor with the
//   password lockout's capped backoff), plugins/two-factor/proofs.ts (a locked factor
//   answers exactly like a wrong code, even with the right code),
//   plugins/two-factor/challenge.ts (5 codes per challenge, then a new password login).
//   A lock never resets the attempt counter (throttle.ts `lock`), so a request that read
//   "no lock" just before the lock was set still counts above the limit. The same burst
//   runs on a real Redis over 16 connections in auth-redis/tests/burst.int.test.ts.
// Learn: Second factors (/auth/learn/second-factors/), Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import type { CounterStore } from '../../src';
import { manualClock, MemoryCounterStore } from '../../src/testing';
import { Throttle } from '../../src/throttle/throttle';
import { meta, twoFactorApp } from '../two-factor/setup';

/**
 * Counters whose lock reads can be made stale: they answer "no lock" as a
 * request would that read the lock a moment before another request set it,
 * the gap a parallel burst over many connections opens on a real store.
 */
function staleLockReads(): { counters: CounterStore; stale: (on: boolean) => void } {
  const inner = new MemoryCounterStore(manualClock(0));
  let stale = false;

  const counters: CounterStore = {
    increment: (key, windowMs) => inner.increment(key, windowMs),
    get: (key) => (stale && key.startsWith('lock:') ? Promise.resolve(null) : inner.get(key)),
    set: (key, count, windowMs) => inner.set(key, count, windowMs),
    decrement: (key) => inner.decrement(key),
    reset: (key) => inner.reset(key),
  };

  return { counters, stale: (on) => (stale = on) };
}

const wrong = (code: string) => (code === '000000' ? '111111' : '000000');

describe('A038: brute forcing the second factor from many IPs', () => {
  it('locks the factor after 5 wrong codes from 5 IPs and refuses the right code while locked, like a wrong one', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    for (let i = 0; i < 5; i++) {
      const { challenge } = await t.challenged();

      const guess = await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'totp', code: wrong(t.codeFor(secret)) },
        meta: meta(`198.51.100.${i}`),
      });

      expect(guess).toMatchObject({
        ok: false,
        code: 'invalid_second_factor',
        reason: 'wrong_code',
      });
    }

    const { challenge } = await t.challenged();

    const right = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta('192.0.2.200'),
    });

    expect(right).toEqual({ ok: false, code: 'invalid_second_factor', reason: 'factor_locked' });

    // The lock lifts after the base lock (5 minutes).
    t.clock.advance(5 * 60_000);

    const later = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(later.ok).toBe(true);
  });

  it('holds a parallel burst over many IPs to the budget', async () => {
    const t = twoFactorApp({ perIp: { limit: 100, window: '1m' } });
    const { secret, session } = await t.enrolled();
    const code = wrong(t.codeFor(secret));

    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        t.auth.twoFactor.stepUp({
          session,
          proof: { kind: 'totp', code },
          meta: meta(`198.51.100.${i}`),
        }),
      ),
    );

    expect(results.filter((r) => !r.ok && r.reason === 'wrong_code')).toHaveLength(5);
    expect(results.filter((r) => !r.ok && r.reason === 'factor_locked')).toHaveLength(45);
  });

  it('refuses attempts that read the lock just before it was set', async () => {
    const { counters, stale } = staleLockReads();
    const throttle = new Throttle(counters, manualClock(0));
    const rule = { limit: 5, window: '15m' };
    const gate = async () => (await throttle.gateFactor('victim', rule)).allowed;
    const first = [];

    for (let i = 0; i < 6; i++) first.push(await gate());

    expect(first).toEqual([true, true, true, true, true, false]);

    // Twenty more that each saw "no lock": none of them gets a guess.
    stale(true);

    const late = [];

    for (let i = 0; i < 20; i++) late.push(await gate());

    expect(late.filter(Boolean)).toEqual([]);
  });

  it('spends a challenge after 5 codes, so each new batch costs a password login', async () => {
    const t = twoFactorApp({ attempts: { limit: 50, window: '15m' } });
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();

    const verify = (code: string, i: number) =>
      t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'totp', code },
        meta: meta(`198.51.100.${i}`),
      });

    for (let i = 0; i < 5; i++) await verify(wrong(t.codeFor(secret)), i);

    expect(await verify(t.codeFor(secret), 9)).toMatchObject({
      ok: false,
      reason: 'challenge_exhausted',
    });
  });

  it('counts recovery-code guesses in the same budget', async () => {
    const t = twoFactorApp();
    const { secret, session } = await t.enrolled();

    for (let i = 0; i < 5; i++)
      await t.auth.twoFactor.stepUp({
        session,
        proof: { kind: 'recovery-code', code: 'aaaaa-aaaaa' },
        meta: meta(),
      });

    const step = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(!step.ok && step.reason).toBe('factor_locked');
  });
});
