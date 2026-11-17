// A037: submitting one TOTP code twice at the same moment.
//
// Two requests carry the same code at once (a double click, or an attacker
// racing the owner with a code they watched being typed). A check-then-write
// replay guard lets both through: each reads the old last step before either
// writes the new one.
//
// Stopped by: plugins/two-factor/proofs.ts (the step is advanced by compare-and-set, and
//   only the request that moved it is accepted), ports/two-factor.ts (`advanceStep`:
//   of many concurrent callers with one step, at most one wins; conformance checks it
//   with 50 callers), plugins/two-factor/challenge.ts (the challenge is spent atomically).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, twoFactorApp } from '../two-factor/setup';

describe('A037: submitting one TOTP code twice at the same moment', () => {
  it('lets exactly one of many concurrent submissions of one code through, on one challenge', async () => {
    const t = twoFactorApp({ perIp: { limit: 100, window: '1m' } });
    const { secret } = await t.enrolled();
    const { challenge } = await t.challenged();
    const code = t.codeFor(secret);

    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        t.auth.twoFactor.verifyChallenge({
          challenge,
          proof: { kind: 'totp', code },
          meta: meta(),
        }),
      ),
    );

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('lets exactly one step-up in many concurrent ones spend a code', async () => {
    const t = twoFactorApp({
      perIp: { limit: 100, window: '1m' },
      attempts: { limit: 100, window: '15m' },
    });

    const { secret, session } = await t.enrolled();
    const code = t.codeFor(secret);

    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        t.auth.twoFactor.stepUp({ session, proof: { kind: 'totp', code }, meta: meta() }),
      ),
    );

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok && r.reason === 'code_replayed')).toHaveLength(19);
  });
});
