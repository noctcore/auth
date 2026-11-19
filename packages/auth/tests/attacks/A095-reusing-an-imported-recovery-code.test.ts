// A095: reusing an imported recovery code.
//
// An app moving onto the plugin carries its users' old recovery codes over
// (`importedRecoveryCodes`). Those hashes came from a weaker scheme (here an
// unsalted SHA-256, not bound to the user), so an attacker who saw one code
// tries it twice, races two uses of it, keeps trying the rest of the old set
// after the owner moved on, copies the old rows onto another account, or burns
// one through a challenge that was never going to pass.
//
// Stopped by: plugins/two-factor/proofs.ts (an imported code is accepted only
//   if the store deletes it, under a prefix the plugin's own hash never takes;
//   spending one at login replaces the whole set, so the old hashes leave the
//   store), plugins/two-factor/recovery-codes.ts (`importedRecoveryCodeHashes`),
//   ports/two-factor.ts (`consumeRecoveryCode` is atomic; conformance checks it).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import {
  importLegacyCodes,
  LEGACY_CODES,
  legacyScheme,
  meta,
  twoFactorApp,
  type TwoFactorApp,
} from '../two-factor/setup';

const code = LEGACY_CODES[0] ?? '';

function app(overrides: Parameters<typeof twoFactorApp>[0] = {}) {
  return twoFactorApp({ importedRecoveryCodes: legacyScheme, ...overrides });
}

async function viaChallenge(t: TwoFactorApp, typed: string, email?: string) {
  return t.auth.twoFactor.verifyChallenge({
    challenge: (await t.challenged(email)).challenge,
    proof: { kind: 'recovery-code', code: typed },
    meta: meta(),
  });
}

describe('A095: reusing an imported recovery code', () => {
  it('accepts an imported code once', async () => {
    const t = app();
    const { session, userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    const stepUp = () =>
      t.auth.twoFactor.stepUp({ session, proof: { kind: 'recovery-code', code }, meta: meta() });

    expect((await stepUp()).ok).toBe(true);
    expect(await stepUp()).toMatchObject({ ok: false, reason: 'wrong_recovery_code' });
    expect(await viaChallenge(t, code)).toMatchObject({ ok: false, reason: 'wrong_recovery_code' });
  });

  it('lets one of many concurrent uses of one imported code through', async () => {
    const t = app({ perIp: { limit: 100, window: '1m' }, attempts: { limit: 100, window: '15m' } });
    const { session, userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        t.auth.twoFactor.stepUp({ session, proof: { kind: 'recovery-code', code }, meta: meta() }),
      ),
    );

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('voids the rest of the old set once the owner signs in with one', async () => {
    const t = app();
    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);
    expect((await viaChallenge(t, code)).ok).toBe(true);

    for (const old of LEGACY_CODES)
      expect(await viaChallenge(t, old)).toMatchObject({
        ok: false,
        reason: 'wrong_recovery_code',
      });
  });

  it('spends no imported code on a challenge from another client', async () => {
    const t = app();
    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    const stolen = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'recovery-code', code },
      meta: { ...meta('198.51.100.1'), userAgent: 'attacker' },
    });

    expect(!stolen.ok && stolen.reason).toBe('client_mismatch');
    expect(await t.store.countRecoveryCodes(userId)).toBe(LEGACY_CODES.length);
  });

  it('matches an imported row only for the account it was imported onto', async () => {
    const t = app();
    const ada = await t.enrolled();
    const grace = await t.enrolled('grace@example.com');

    await importLegacyCodes(t.store, ada.userId);

    // Grace's own set is the plugin's: Ada's old code is nothing to her account.
    expect(await viaChallenge(t, code, 'grace@example.com')).toMatchObject({
      ok: false,
      reason: 'wrong_recovery_code',
    });

    expect(await t.store.countRecoveryCodes(ada.userId)).toBe(LEGACY_CODES.length);
    expect(await t.store.countRecoveryCodes(grace.userId)).toBe(10);
  });
});
