// A041: reusing a recovery code.
//
// A recovery code is written on paper or kept in a password manager; whoever
// sees it once could use it again, or two requests race to spend it, or an old
// set kept after the user regenerated still works.
//
// Stopped by: plugins/two-factor/proofs.ts (a code is accepted only if the store deleted
//   it), ports/two-factor.ts (`consumeRecoveryCode` is atomic, `replaceRecoveryCodes`
//   swaps the whole set in one write; conformance checks both),
//   plugins/two-factor/management.ts (regenerating needs a step-up).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, twoFactorApp } from '../two-factor/setup';

describe('A041: reusing a recovery code', () => {
  it('accepts a recovery code once', async () => {
    const t = twoFactorApp();
    const { recoveryCodes } = await t.enrolled();
    const code = recoveryCodes[0] ?? '';

    const use = async () =>
      t.auth.twoFactor.verifyChallenge({
        challenge: (await t.challenged()).challenge,
        proof: { kind: 'recovery-code', code },
        meta: meta(),
      });

    expect((await use()).ok).toBe(true);

    expect(await use()).toMatchObject({
      ok: false,
      code: 'invalid_second_factor',
      reason: 'wrong_recovery_code',
    });
  });

  it('lets one of many concurrent uses of one code through', async () => {
    const t = twoFactorApp({
      perIp: { limit: 100, window: '1m' },
      attempts: { limit: 100, window: '15m' },
    });

    const { recoveryCodes, session } = await t.enrolled();
    const code = recoveryCodes[0] ?? '';

    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        t.auth.twoFactor.stepUp({ session, proof: { kind: 'recovery-code', code }, meta: meta() }),
      ),
    );

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('voids every old code when the set is regenerated', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, session } = await t.enrolled();

    await t.auth.twoFactor.regenerateRecoveryCodes({ session, meta: meta() });

    for (const code of recoveryCodes.slice(0, 3)) {
      const used = await t.auth.twoFactor.verifyChallenge({
        challenge: (await t.challenged()).challenge,
        proof: { kind: 'recovery-code', code },
        meta: meta(),
      });

      expect(!used.ok && used.reason).toBe('wrong_recovery_code');
    }
  });

  it('stores only an HMAC bound to the user: a row copied onto another account matches nothing', async () => {
    const t = twoFactorApp();
    const ada = await t.enrolled();
    const grace = await t.enrolled('grace@example.com');
    const codes = (t.store as unknown as { recoveryCodes: Map<string, Set<string>> }).recoveryCodes;

    for (const hash of codes.get(ada.userId) ?? []) {
      for (const code of ada.recoveryCodes) expect(hash).not.toContain(code.replace('-', ''));
    }

    codes.set(grace.userId, new Set(codes.get(ada.userId)));

    const used = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged('grace@example.com')).challenge,
      proof: { kind: 'recovery-code', code: ada.recoveryCodes[0] ?? '' },
      meta: meta(),
    });

    expect(!used.ok && used.reason).toBe('wrong_recovery_code');
  });
});
