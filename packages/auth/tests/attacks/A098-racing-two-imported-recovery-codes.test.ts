// A098: racing two logins with two imported recovery codes.
//
// A login that passes the challenge with an imported recovery code replaces
// the user's whole set and shows the new codes once (A095). Two logins at once
// with two different imported codes (the owner on two devices, or the owner
// and an attacker who holds one old code) both pass their check before either
// replaces the set. If both replaced it, the last write would win and one of
// the two shown sets would be dead: the owner could write down codes that
// never work.
//
// Stopped by: plugins/two-factor/proofs.ts (`rotateImportedSet`: only the
//   login that claims the rotation, an atomic counter increment, replaces the
//   set; the other keeps its session and is shown no codes),
//   plugins/two-factor/challenge.ts (the spent code is reported once the set
//   is settled, with the count the user ends with).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it, vi } from 'vitest';

import {
  importLegacyCodes,
  LEGACY_CODES,
  legacyScheme,
  meta,
  twoFactorApp,
} from '../two-factor/setup';

const [first = '', second = ''] = LEGACY_CODES;

describe('A098: racing two logins with two imported recovery codes', () => {
  it('leaves exactly one live set, shown to exactly one of the two logins', async () => {
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    let holdNext = false;
    let entered = false;

    // The first login waits inside session issue, after its code passed and
    // its challenge was spent, while the second login runs to the end.
    const t = twoFactorApp(
      { importedRecoveryCodes: legacyScheme },
      {
        hooks: {
          beforeSessionCreate: async () => {
            if (!holdNext) return;

            holdNext = false;
            entered = true;
            await held;
          },
        },
      },
    );

    const { userId } = await t.enrolled();

    await importLegacyCodes(t.store, userId);

    const verify = (challenge: string, code: string) =>
      t.auth.twoFactor.verifyChallenge({
        challenge,
        proof: { kind: 'recovery-code', code },
        meta: meta(),
      });

    const { challenge } = await t.challenged();

    holdNext = true;

    const slow = verify(challenge, first);

    await vi.waitFor(() => expect(entered).toBe(true));

    const fast = await verify((await t.challenged()).challenge, second);

    release();

    const late = await slow;

    expect(fast.ok && late.ok).toBe(true);

    const shown = [fast, late].map((r) => (r.ok ? r.value.recoveryCodes : null));

    expect(shown.filter((codes) => codes !== null)).toHaveLength(1);
    expect(await t.store.countRecoveryCodes(userId)).toBe(10);

    // The set that was shown is the live one.
    const live = shown.find((codes) => codes !== null) ?? [];
    const session = fast.ok ? fast.value.session.session : null;

    if (!session) throw new Error('expected a session');

    for (const code of live.slice(0, 2))
      expect(
        (
          await t.auth.twoFactor.stepUp({
            session,
            proof: { kind: 'recovery-code', code },
            meta: meta(),
          })
        ).ok,
      ).toBe(true);
  });
});
