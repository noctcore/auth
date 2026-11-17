// A063: stripping the owner's second factor with an email revert.
//
// The owner signs in, enrols a second factor and, in the same session, moves
// the account off an old address whose mailbox someone else now reads. That
// someone clicks the revert link mailed to the old address. If a revert
// removed factors enrolled after the asking session began, it would delete
// the owner's factor, and the reset the revert asks for (mailed to the
// address they control) would then need nothing else.
//
// Stopped by: flows/email-change.ts (a revert never removes a second factor;
//   it cannot tell the owner's factor from one an intruder enrolled), and
//   plugins/two-factor/hooks.ts (a reset still asks for the factor). The cost:
//   an owner who cannot pass a factor the intruder enrolled needs support.
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, queuedTwoFactor } from './support';
import { changed } from '../flows/email-change-support';

const OLD = 'ada@example.com';

describe("A063: stripping the owner's second factor with an email revert", () => {
  it('a revert from the old mailbox keeps the factor the owner enrolled in the session that asked, and a reset without it is refused', async () => {
    const t = queuedTwoFactor();
    const { session } = await t.signedIn(OLD);
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    expect(confirmed.ok).toBe(true);

    t.nextStep();

    const moved = await changed(t, session, 'ada@new.example');
    const elsewhere = meta('198.51.100.23');

    expect((await t.auth.revertEmailChange({ token: moved.revert, meta: elsewhere })).ok).toBe(
      true,
    );

    expect(await t.store.findFactor(session.userId)).toMatchObject({ confirmed: true });
    expect(await t.store.countRecoveryCodes(session.userId)).toBeGreaterThan(0);

    const reset = await t.resetLinkFor(OLD, '198.51.100.23');

    expect(reset).not.toBe('');

    expect(
      await t.auth.resetPassword({ token: reset, password: 'mine now, thanks', meta: elsewhere }),
    ).toMatchObject({ ok: false, code: 'second_factor_required' });

    expect((await t.stores.users.findCredentialById(session.userId))?.passwordHash).toBeNull();
  });
});
