// A042: brute forcing a recovery code.
//
// Recovery codes skip the authenticator app, so they are what an attacker with
// the password guesses: ten codes in the set means ten chances per guess.
//
// Stopped by: plugins/two-factor/recovery-codes.ts (10 codes of 50 bits each from the
//   CSPRNG: about 2^47 guesses per hit), throttle/throttle.ts and
//   plugins/two-factor/proofs.ts (every recovery-code guess spends the account's factor
//   budget before the lookup, and a locked factor refuses even a right code).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { generateRecoveryCodes } from '../../src/plugins/two-factor/recovery-codes';
import { meta, twoFactorApp } from '../two-factor/setup';

describe('A042: brute forcing a recovery code', () => {
  it('draws codes of 50 bits from the random source', () => {
    const codes = generateRecoveryCodes(globalThis.crypto.getRandomValues.bind(globalThis.crypto));
    const symbols = new Set(codes.join('').replaceAll('-', ''));

    expect(codes).toHaveLength(10);
    expect(codes.every((code) => code.replace('-', '').length === 10)).toBe(true);
    expect(symbols.size).toBeGreaterThan(16);
  });

  it('locks after 5 wrong guesses from many IPs, then refuses a right code like a wrong one', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, userId } = await t.enrolled();

    for (let i = 0; i < 5; i++) {
      const guess = await t.auth.twoFactor.verifyChallenge({
        challenge: (await t.challenged()).challenge,
        proof: { kind: 'recovery-code', code: `${String(i).repeat(5)}-aaaaa` },
        meta: meta(`198.51.100.${i}`),
      });

      expect(guess).toMatchObject({ ok: false, code: 'invalid_second_factor' });
    }

    const right = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'recovery-code', code: recoveryCodes[0] ?? '' },
      meta: meta('192.0.2.50'),
    });

    expect(right).toEqual({ ok: false, code: 'invalid_second_factor', reason: 'factor_locked' });
    expect(await t.store.countRecoveryCodes(userId)).toBe(10);
  });

  it('does not spend a code while the factor is locked', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, userId, session } = await t.enrolled();

    for (let i = 0; i < 6; i++)
      await t.auth.twoFactor.stepUp({
        session,
        proof: { kind: 'recovery-code', code: 'zzzzz-zzzzz' },
        meta: meta(),
      });

    await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'recovery-code', code: recoveryCodes[0] ?? '' },
      meta: meta(),
    });

    expect(await t.store.countRecoveryCodes(userId)).toBe(10);
  });
});
