// A047: telling a wrong code from an unknown challenge or a missing factor by timing.
//
// The answer text is the same, but an implementation that returns early for an
// unknown challenge, or for a user without a factor, skips the decrypt and the
// code work a wrong code pays for, and the difference shows in the response
// time.
//
// Stopped by: plugins/two-factor/challenge.ts (an unknown challenge makes the same store
//   calls under a key of its own), plugins/two-factor/proofs.ts (no factor, or a locked
//   one, still decrypts a stand-in secret and computes every code in the window).
//   Checked by counting calls, not wall-clock time.
// Learn: Second factors (/auth/learn/second-factors/), Enumeration (/auth/learn/enumeration/)
import { describe, expect, it } from 'vitest';

import { meta, recordTwoFactorCalls, twoFactorApp, unknownToken } from '../two-factor/setup';
import { recordStoreCalls } from './support';

function traced() {
  const t = twoFactorApp({
    perIp: { limit: 1000, window: '1m' },
    attempts: { limit: 1000, window: '15m' },
  });

  const { calls } = recordStoreCalls(t.stores);

  recordTwoFactorCalls(t.store, calls);

  const trace = async (run: () => Promise<unknown>) => {
    calls.length = 0;
    t.cipherCalls.decrypt = 0;
    t.cipherCalls.encrypt = 0;

    const answer = await run();

    return {
      calls: [...calls],
      decrypts: t.cipherCalls.decrypt,
      encrypts: t.cipherCalls.encrypt,
      answer,
    };
  };

  return { t, trace };
}

const publicPart = (answer: unknown) => {
  const { code } = answer as { code?: string };

  return code;
};

describe('A047: telling a wrong code from an unknown challenge or a missing factor by timing', () => {
  it('makes the same store calls and decrypts once for an unknown challenge and for a wrong code', async () => {
    const { t, trace } = traced();
    const { secret } = await t.enrolled();

    const verify = (challenge: string, code: string) =>
      t.auth.twoFactor.verifyChallenge({ challenge, proof: { kind: 'totp', code }, meta: meta() });

    // The stand-in secret is encrypted once, on first use.
    await verify(unknownToken(), '000000');

    const { challenge } = await t.challenged();
    const wrongCode = t.codeFor(secret) === '000000' ? '111111' : '000000';
    const wrong = await trace(() => verify(challenge, wrongCode));
    const unknown = await trace(() => verify(unknownToken(), wrongCode));

    expect(unknown.calls).toEqual(wrong.calls);
    expect(unknown.decrypts).toBe(1);
    expect(wrong.decrypts).toBe(1);
    expect(unknown.encrypts).toBe(0);
    expect(publicPart(unknown.answer)).toBe(publicPart(wrong.answer));
  });

  it('makes the same calls for a step-up of a user without a factor as for a wrong code', async () => {
    const { t, trace } = traced();
    const ada = await t.enrolled();
    const grace = await t.signedIn('grace@example.com');

    const proof = {
      kind: 'totp' as const,
      code: t.codeFor(ada.secret) === '000000' ? '111111' : '000000',
    };

    await t.auth.twoFactor.stepUp({ session: grace.session, proof, meta: meta() });

    const wrong = await trace(() =>
      t.auth.twoFactor.stepUp({ session: ada.session, proof, meta: meta() }),
    );

    const none = await trace(() =>
      t.auth.twoFactor.stepUp({ session: grace.session, proof, meta: meta() }),
    );

    expect(none.calls).toEqual(wrong.calls);
    expect(none.decrypts).toBe(wrong.decrypts);
    expect(publicPart(none.answer)).toBe(publicPart(wrong.answer));
  });

  it('makes the same calls for a recovery code on an unknown challenge and a wrong one', async () => {
    const { t, trace } = traced();

    await t.enrolled();

    const { challenge } = await t.challenged();

    const verify = (c: string) =>
      t.auth.twoFactor.verifyChallenge({
        challenge: c,
        proof: { kind: 'recovery-code', code: 'aaaaa-aaaaa' },
        meta: meta(),
      });

    const wrong = await trace(() => verify(challenge));
    const unknown = await trace(() => verify(unknownToken()));

    expect(unknown.calls).toEqual(wrong.calls);
    expect(publicPart(unknown.answer)).toBe(publicPart(wrong.answer));
  });

  it('does the same work for a locked factor as for an open one, apart from the spent budget', async () => {
    const t = twoFactorApp();
    const { calls } = recordStoreCalls(t.stores);

    recordTwoFactorCalls(t.store, calls);

    const { secret, session } = await t.enrolled();

    const proof = {
      kind: 'totp' as const,
      code: t.codeFor(secret) === '000000' ? '111111' : '000000',
    };

    const trace = async () => {
      calls.length = 0;
      t.cipherCalls.decrypt = 0;

      const answer = await t.auth.twoFactor.stepUp({ session, proof, meta: meta() });

      return { calls: [...calls], decrypts: t.cipherCalls.decrypt, answer };
    };

    const open = await trace();

    for (let i = 0; i < 5; i++) await trace();

    const locked = await trace();

    // Under a lock the gate stops before it spends the budget, so it makes
    // fewer counter calls; every other call and the decrypt match.
    const outsideCounters = (list: string[]) =>
      list.filter((call) => !call.startsWith('counters.'));

    expect(!locked.answer.ok && locked.answer.reason).toBe('factor_locked');
    expect(outsideCounters(locked.calls)).toEqual(outsideCounters(open.calls));
    expect(locked.decrypts).toBe(open.decrypts);
    expect(publicPart(locked.answer)).toBe(publicPart(open.answer));
  });
});
