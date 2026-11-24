// A112: guessing second-factor codes, or learning who has a factor, through
// the doors an app calls without a password login.
//
// `twoFactor.challenge` starts a challenge for a user the app authenticated
// itself, and `twoFactor.verifyProof` checks a code for a user an app flow
// identified without a session. If either had a budget of its own, a guesser
// could spread codes across them and the login challenge; if a wrong code
// answered differently from a user with no factor, or from no user at all,
// the proof door would tell who has one.
//
// Stopped by: plugins/two-factor/step-up.ts (`verifyProof` checks through
//   `checkProof`, on the factor's own lock key and the plugin's per-IP limit, and
//   answers a user without a confirmed factor, given a proof, as a wrong code after
//   the same store calls), plugins/two-factor/challenge.ts (`startChallenge` only
//   makes the login's challenge, behind the per-IP limit; codes are counted at the
//   verify), plugins/two-factor/proofs.ts (`checkProof`).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, recordTwoFactorCalls, twoFactorApp } from '../two-factor/setup';

const WRONG = { kind: 'totp', code: '000000' } as const;

describe('A112: guessing codes through the app doors', () => {
  it('counts proof-door guesses on the same lock as the login challenge', async () => {
    const t = twoFactorApp();
    const { userId, secret } = await t.enrolled();

    for (let i = 0; i < 3; i += 1)
      await t.auth.twoFactor.verifyProof({ userId, proof: WRONG, action: 'x', meta: meta() });

    for (let i = 0; i < 2; i += 1) {
      const { challenge } = await t.challenged();

      await t.auth.twoFactor.verifyChallenge({ challenge, proof: WRONG, meta: meta() });
    }

    // The budget (5) is spent across both doors: the right code is locked out on each.
    const proof = { kind: 'totp', code: t.codeFor(secret) } as const;

    expect(
      await t.auth.twoFactor.verifyProof({ userId, proof, action: 'x', meta: meta() }),
    ).toMatchObject({ ok: false, reason: 'x_second_factor_factor_locked' });

    const { challenge } = await t.challenged();
    const locked = await t.auth.twoFactor.verifyChallenge({ challenge, proof, meta: meta() });

    expect(locked).toMatchObject({ ok: false, code: 'invalid_second_factor' });
  });

  it('answers a wrong code, a user without a factor and no user alike, after the same store calls', async () => {
    const t = twoFactorApp();
    const { userId } = await t.enrolled();
    const plain = await t.signedIn('grace@example.com');

    const probe = async (id: string) => {
      const calls: string[] = [];

      recordTwoFactorCalls(t.store, calls);

      const result = await t.auth.twoFactor.verifyProof({
        userId: id,
        proof: WRONG,
        action: 'x',
        meta: meta(),
      });

      return { code: result.ok ? 'ok' : result.code, calls: calls.join(' ') };
    };

    const wrong = await probe(userId);
    const factorless = await probe(plain.session.userId);
    const nobody = await probe('no-such-user');

    expect(wrong.code).toBe('invalid_second_factor');
    expect(factorless).toEqual(wrong);
    expect(nobody).toEqual(wrong);
  });

  it('puts the proof door and the challenge door behind the plugin per-IP limit', async () => {
    const t = twoFactorApp({ perIp: { limit: 3, window: '15m' } });
    const { userId } = await t.enrolled();
    const ip = '198.51.100.20';

    await t.auth.twoFactor.challenge({ userId, meta: meta(ip) });
    await t.auth.twoFactor.verifyProof({ userId, proof: WRONG, action: 'x', meta: meta(ip) });
    await t.auth.twoFactor.verifyProof({ userId, proof: WRONG, action: 'x', meta: meta(ip) });

    expect(
      await t.auth.twoFactor.verifyProof({ userId, proof: WRONG, action: 'x', meta: meta(ip) }),
    ).toMatchObject({ ok: false, code: 'rate_limited' });

    expect(await t.auth.twoFactor.challenge({ userId, meta: meta(ip) })).toMatchObject({
      ok: false,
      code: 'rate_limited',
    });
  });

  it('never hands out a session from the challenge door without the factor', async () => {
    const t = twoFactorApp();
    const { userId } = await t.enrolled();
    const started = await t.auth.twoFactor.challenge({ userId, meta: meta() });

    expect(started.ok && started.value && 'session' in started.value).toBe(false);

    if (!started.ok || !started.value) throw new Error('expected a challenge');

    const done = await t.auth.twoFactor.verifyChallenge({
      challenge: started.value.challenge,
      proof: WRONG,
      meta: meta(),
    });

    expect(done).toMatchObject({ ok: false, code: 'invalid_second_factor' });
  });
});
