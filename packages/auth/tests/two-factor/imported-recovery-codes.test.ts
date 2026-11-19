// Recovery codes imported from an app's earlier scheme (`importedRecoveryCodes`):
// accepted once each, the set moved onto the plugin's own codes at login, and
// nothing accepted without the option.
import { describe, expect, it } from 'vitest';

import {
  EMAIL,
  importLegacyCodes,
  LEGACY_CODES,
  legacyHash,
  legacyScheme,
  meta,
  NEW_PASSWORD,
  PASSWORD,
  twoFactorApp,
  type TwoFactorApp,
} from './setup';
import { importedRecoveryCodeHashes, twoFactor } from '../../src/plugins/two-factor';
import { MemoryTwoFactorStore } from '../../src/testing';

const legacy = (i: number) => LEGACY_CODES[i] ?? '';

async function viaChallenge(t: TwoFactorApp, code: string) {
  return t.auth.twoFactor.verifyChallenge({
    challenge: (await t.challenged()).challenge,
    proof: { kind: 'recovery-code', code },
    meta: meta(),
  });
}

describe('imported recovery codes', () => {
  it('passes the login challenge with an imported code and replaces the whole set with new codes', async () => {
    const t = twoFactorApp({ importedRecoveryCodes: legacyScheme });
    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    const done = await viaChallenge(t, legacy(0).toLowerCase().replaceAll('-', ' '));

    expect(done.ok).toBe(true);

    const fresh = done.ok ? (done.value.recoveryCodes ?? []) : [];

    expect(fresh).toHaveLength(10);
    expect(await t.store.countRecoveryCodes(userId)).toBe(10);

    // The other imported codes left the store with the old set.
    expect(await viaChallenge(t, legacy(1))).toMatchObject({
      ok: false,
      reason: 'wrong_recovery_code',
    });

    // The new codes are the plugin's own and work like any other.
    const next = await viaChallenge(t, fresh[0] ?? '');

    expect(next.ok && next.value.recoveryCodes).toBeNull();
    expect(await t.store.countRecoveryCodes(userId)).toBe(9);
  });

  it('records the import in the audit row and mails the count of the new set', async () => {
    const t = twoFactorApp({ importedRecoveryCodes: legacyScheme });
    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);
    expect((await viaChallenge(t, legacy(0))).ok).toBe(true);

    await Promise.resolve();
    expect(t.mailer.last('recovery-code-used')).toMatchObject({ to: EMAIL, userId, remaining: 10 });

    expect(t.audit.events.find((e) => e.type === 'two_factor.recovery_code_used')?.data).toEqual({
      remaining: 10,
      imported: true,
    });

    expect(t.audit.events.some((e) => e.type === 'two_factor.recovery_codes_generated')).toBe(true);
  });

  it('spends an imported code on a step-up without replacing the set (nothing could show new codes)', async () => {
    const t = twoFactorApp({ importedRecoveryCodes: legacyScheme });
    const { userId, session } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    const stepUp = (code: string) =>
      t.auth.twoFactor.stepUp({ session, proof: { kind: 'recovery-code', code }, meta: meta() });

    expect((await stepUp(legacy(0))).ok).toBe(true);
    expect(await t.store.countRecoveryCodes(userId)).toBe(2);
    expect(await stepUp(legacy(0))).toMatchObject({ ok: false, reason: 'wrong_recovery_code' });
    expect((await stepUp(legacy(1))).ok).toBe(true);
    expect(await t.store.countRecoveryCodes(userId)).toBe(1);
  });

  it('accepts an imported code as the second factor of a password change, once', async () => {
    const t = twoFactorApp({ importedRecoveryCodes: legacyScheme });
    const { secret, userId } = await t.enrolled();
    const session = (await t.passed(secret)).session;

    await importLegacyCodes(t.store, userId);
    // Past the step-up window, so the change needs a code with the request.
    t.clock.advance(10 * 60_000);

    const change = (newPassword: string) =>
      t.auth.changePassword({
        session,
        currentPassword: PASSWORD,
        newPassword,
        secondFactor: legacy(0),
        meta: meta(),
      });

    expect((await change(NEW_PASSWORD)).ok).toBe(true);
    expect(await t.store.countRecoveryCodes(userId)).toBe(2);
  });

  it('accepts nothing imported without the option', async () => {
    const t = twoFactorApp();
    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    for (const code of LEGACY_CODES)
      expect(await viaChallenge(t, code)).toMatchObject({
        ok: false,
        code: 'invalid_second_factor',
        reason: 'malformed_recovery_code',
      });

    expect(await t.store.countRecoveryCodes(userId)).toBe(3);
  });

  it('never matches a hash imported without the prefix', async () => {
    const t = twoFactorApp({ importedRecoveryCodes: legacyScheme });
    const { userId } = await t.enrolled();

    await t.store.replaceRecoveryCodes(userId, [legacyHash(legacy(0)) ?? '']);

    expect(await viaChallenge(t, legacy(0))).toMatchObject({
      ok: false,
      reason: 'wrong_recovery_code',
    });
  });

  it('still accepts the plugin own codes with the option on', async () => {
    const t = twoFactorApp({ importedRecoveryCodes: legacyScheme });
    const { recoveryCodes, userId } = await t.enrolled();
    const done = await viaChallenge(t, recoveryCodes[0] ?? '');

    expect(done.ok && done.value.recoveryCodes).toBeNull();
    expect(await t.store.countRecoveryCodes(userId)).toBe(9);
  });

  it('hands the hash the user id and an async answer counts', async () => {
    const seen: string[] = [];

    const t = twoFactorApp({
      importedRecoveryCodes: {
        hash: async (code, { userId }) => (seen.push(userId), legacyHash(code)),
      },
    });

    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);
    expect((await viaChallenge(t, legacy(2))).ok).toBe(true);
    expect(seen).toEqual([userId]);
  });

  it('hashes the input the same way when there is no factor to check, so it costs what a wrong code costs', async () => {
    let calls = 0;

    const t = twoFactorApp({
      importedRecoveryCodes: { hash: (code) => (calls++, legacyHash(code)) },
    });

    await t.signedIn();

    const unknown = await t.auth.twoFactor.verifyChallenge({
      challenge: 'not-a-challenge',
      proof: { kind: 'recovery-code', code: legacy(0) },
      meta: meta(),
    });

    expect(!unknown.ok && unknown.reason).toBe('challenge_unknown');
    expect(calls).toBe(1);
  });

  it('refuses input too long to be a code, or one the scheme rejects, as malformed', async () => {
    const t = twoFactorApp({ importedRecoveryCodes: legacyScheme });
    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    for (const code of ['x'.repeat(65), 'not a code', ''])
      expect(await viaChallenge(t, code)).toMatchObject({
        ok: false,
        reason: 'malformed_recovery_code',
      });

    expect(await t.store.countRecoveryCodes(userId)).toBe(3);
  });

  it('refuses an option without a hash function, and an empty hash to import', () => {
    const base = { store: new MemoryTwoFactorStore(), cipher: {} as never, issuer: 'Acme' };

    expect(() => twoFactor({ ...base, importedRecoveryCodes: {} as never })).toThrow(
      'importedRecoveryCodes.hash must be a function',
    );

    expect(() => importedRecoveryCodeHashes(['abc', ''])).toThrow('non-empty string');
    expect(importedRecoveryCodeHashes(['abc'])).toEqual(['imported:abc']);
  });
});
