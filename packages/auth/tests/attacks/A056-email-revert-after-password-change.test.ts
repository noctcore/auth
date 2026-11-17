// A056: keeping the account after an email change by changing the password.
//
// The attacker moves the account to their address, then changes the password
// (or resets it from their mailbox) hoping that voids the revert link the old
// address received, or that the new password survives the revert.
//
// Stopped by: flows/email-change.ts (the revert link is a token of its own
//   purpose that password changes and resets never void; a revert removes the
//   password, revokes every session and voids every reset token, so the next
//   sign-in needs a reset mailed to the restored address), flows/password-change.ts
//   and flows/password-reset.ts (they void only the reset purposes).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, NEW_PASSWORD, PASSWORD, queued, tokenOf } from './support';
import { changed } from '../flows/email-change-support';

const OWNER = 'ada@example.com';
const INTRUDER = 'mallory@example.com';

describe('A056: keeping the account after an email change by changing the password', () => {
  it('the revert still works after a password change and leaves the intruder no password', async () => {
    const t = queued();
    const { session } = await t.signedInUser(OWNER);
    const taken = await changed(t, session, INTRUDER);

    const pw = await t.auth.changePassword({
      session: taken.session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    if (!pw.ok) throw new Error(pw.reason);

    expect((await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).ok).toBe(true);
    expect(await t.sessionOf(pw.value.token)).toBeNull();

    for (const [email, password] of [
      [INTRUDER, NEW_PASSWORD],
      [OWNER, NEW_PASSWORD],
      [OWNER, PASSWORD],
    ] as const) {
      expect((await t.auth.login({ email, password, meta: meta('198.51.100.30') })).ok).toBe(false);
    }

    expect((await t.stores.users.findCredentialById(session.userId))?.passwordHash).toBeNull();
  });

  it('the revert works after a reset from the intruder mailbox, and voids a reset link still in it', async () => {
    const t = queued();
    const { session } = await t.signedInUser(OWNER);
    const taken = await changed(t, session, INTRUDER);

    await t.auth.requestPasswordReset({ email: INTRUDER, meta: meta() });
    await t.drain();

    const used = tokenOf(t.mailer.last('password-reset')?.url);

    expect(
      (await t.auth.resetPassword({ token: used, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(true);

    t.clock.advance(60_000);
    await t.auth.requestPasswordReset({ email: INTRUDER, meta: meta() });
    await t.drain();

    const spare = tokenOf(t.mailer.last('password-reset')?.url);

    expect((await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).ok).toBe(true);

    expect(
      await t.auth.resetPassword({ token: spare, password: 'intruder keeps trying', meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });

    // A reset now goes to the restored address only.
    await t.auth.requestPasswordReset({ email: INTRUDER, meta: meta('198.51.100.31') });
    await t.auth.requestPasswordReset({ email: OWNER, meta: meta('198.51.100.31') });
    await t.drain();

    expect(t.mailer.last('password-reset')?.to).toBe(OWNER);
  });
});
