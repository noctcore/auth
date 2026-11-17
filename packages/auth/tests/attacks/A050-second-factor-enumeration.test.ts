// A050: learning account state from second-factor answers.
//
// Whether an address has two-factor on, whether a factor is locked, whether a
// challenge exists: any of these, read from a wrong password's answer or from
// the code a challenge refusal carries, tells an attacker which accounts are
// worth phishing and when to try.
//
// Stopped by: flows/login.ts (the factor is only looked at after a correct password, so a
//   wrong password answers and works the same whether or not the account has one),
//   plugins/two-factor/challenge.ts and plugins/two-factor/proofs.ts (an unknown, spent
//   or foreign challenge, a wrong code, a replayed code and a locked factor all answer
//   `invalid_second_factor`; the reason is for the audit row only).
// Learn: Second factors (/auth/learn/second-factors/), Enumeration (/auth/learn/enumeration/)
import { describe, expect, it } from 'vitest';

import { toPublicError } from '../../src';
import { meta, recordTwoFactorCalls, twoFactorApp, unknownToken } from '../two-factor/setup';
import { recordStoreCalls } from './support';

describe('A050: learning account state from second-factor answers', () => {
  it('answers a wrong password the same, with the same calls, for accounts with and without a factor', async () => {
    const t = twoFactorApp();

    await t.enrolled();
    await t.signedIn('grace@example.com');

    const { calls } = recordStoreCalls(t.stores);

    recordTwoFactorCalls(t.store, calls);

    const trace = async (email: string) => {
      calls.length = 0;

      const answer = await t.auth.login({ email, password: 'wrong passphrase!', meta: meta() });

      return { calls: [...calls], answer: answer.ok ? null : toPublicError(answer) };
    };

    const withFactor = await trace('ada@example.com');
    const without = await trace('grace@example.com');

    expect(withFactor).toEqual(without);
    expect(withFactor.calls.some((call) => call.startsWith('twoFactor.'))).toBe(false);
  });

  it('gives every refused code the same public answer', async () => {
    const t = twoFactorApp({ perIp: { limit: 100, window: '1m' } });
    const { secret, session } = await t.enrolled();
    const answers = new Set<string>();
    let ip = 0;

    // Each login from its own address, so the login's per-IP limit stays out of the way.
    const fresh = async () =>
      (await t.challenged(undefined, { ip: `198.51.100.${++ip}` })).challenge;

    const verify = async (challenge: string, code: string, userAgent = 'vitest') => {
      const result = await t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'totp', code },
        meta: { ...meta(), userAgent },
      });

      if (result.ok) throw new Error('unexpected pass');

      answers.add(JSON.stringify(toPublicError(result)));

      return result.reason;
    };

    const reasons = [
      await verify(unknownToken(), '123456'),
      await verify(await fresh(), '000000'),
      await verify(await fresh(), t.codeFor(secret), 'another browser'),
    ];

    // Spend the code, then replay it; then lock the factor.
    const used = t.codeFor(secret);

    await t.auth.twoFactor.verifyChallenge({
      challenge: await fresh(),
      proof: { kind: 'totp', code: used },
      meta: meta(),
    });

    reasons.push(await verify(await fresh(), used));

    // Lock the factor by step-up guesses (logins have a budget of their own).
    for (let i = 0; i < 5; i++)
      await t.auth.twoFactor.stepUp({
        session,
        proof: { kind: 'totp', code: '000000' },
        meta: meta(),
      });

    t.nextStep();
    reasons.push(await verify(await fresh(), t.codeFor(secret)));

    expect(reasons).toEqual(
      expect.arrayContaining([
        'challenge_unknown',
        'wrong_code',
        'client_mismatch',
        'code_replayed',
        'factor_locked',
      ]),
    );

    expect([...answers]).toEqual([JSON.stringify({ code: 'invalid_second_factor' })]);
  });
});
