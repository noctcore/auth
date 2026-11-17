// A062: resetting the password at the intruder's address after a refused revert.
//
// The old address got an account anyway (a path of the app that creates users
// without asking for the hold, or a race with sign-up), so the owner's revert
// cannot restore it. The account still names the intruder's address B. The
// revert removed the password and every session, but a reset mailed to B, a
// reset link issued earlier, or a session minted by the app's own SSO would
// hand the account straight back.
//
// Stopped by: flows/email-lockout.ts (a refused revert locks the account out:
//   no session is issued for it, a reset request for it sends nothing and a
//   reset link for it is refused, each with the ordinary answer and before
//   any password is hashed; the lockout never lapses, and the owner's revert
//   link lives as long), flows/email-change.ts (the
//   revert sets the lockout right after the write that removed the password,
//   and a finished revert ends it), create-auth.ts (`clearEmailRevertLockout`
//   for support, `isAddressHeld` for the app's own user-creating paths).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it, vi } from 'vitest';

import { meta, PASSWORD, queued, requestAndDrain, tokenOf } from './support';
import { changed } from '../flows/email-change-support';

const OWNER = 'ada@example.com';
const INTRUDER = 'mallory@example.com';

/** An account moved from OWNER to INTRUDER, OWNER taken past the hold, and the owner's revert refused. */
async function refusedRevert() {
  const t = queued();
  const { session } = await t.signedInUser(OWNER);
  const taken = await changed(t, session, INTRUDER);

  // An app path that created a user without asking `auth.isAddressHeld`.
  const squatter = await t.stores.users.create({ email: OWNER as never, passwordHash: 'x' });

  expect(await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).toMatchObject({
    ok: false,
    reason: 'email_revert_address_taken',
  });

  return { t, userId: session.userId, revert: taken.revert, squatterId: squatter?.id ?? '' };
}

describe('A062: resetting the password at the intruder address after a refused revert', () => {
  it('a reset request for the intruder address sends nothing and answers as usual', async () => {
    const { t, userId } = await refusedRevert();
    const before = t.mailer.sent.length;

    expect(await t.auth.requestPasswordReset({ email: INTRUDER, meta: meta() })).toEqual({
      ok: true,
      value: undefined,
    });

    await t.drain();

    expect(t.mailer.sent.slice(before)).toEqual([]);

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'password.reset_request_ignored',
      userId,
      reason: 'email_revert_lockout',
    });
  });

  it('a reset link issued before the lockout is refused like a dead one, without hashing the password', async () => {
    const { t, userId } = await refusedRevert();

    // Suppose a reset link survived (it is voided by the revert; this one is minted after).
    const link = await t.auth.context.tokens.issueLink('password-reset', userId, 60_000);
    const hash = vi.spyOn(t.auth.context.hasher, 'hash');

    expect(
      await t.auth.resetPassword({
        token: link.token,
        password: 'a brand new passphrase',
        meta: meta(),
      }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });

    expect(hash).not.toHaveBeenCalled();
    expect((await t.stores.users.findCredentialById(userId))?.passwordHash).toBeNull();
  });

  it('no session is issued for the account, even with a password set behind the library', async () => {
    const { t, userId } = await refusedRevert();

    await t.stores.users.setPasswordHash(userId, await t.auth.context.hasher.hash(PASSWORD));

    expect(await t.auth.login({ email: INTRUDER, password: PASSWORD, meta: meta() })).toMatchObject(
      {
        ok: false,
        code: 'invalid_credentials',
      },
    );

    expect(await t.stores.sessions.listByUser(userId)).toEqual([]);
  });

  it('the owner finishes with the same link once the old address is free, after the usual 7 days, and the lockout ends', async () => {
    const { t, userId, revert, squatterId } = await refusedRevert();

    t.clock.advance(30 * 24 * 60 * 60_000);
    await t.stores.users.setEmail(squatterId, 'elsewhere@example.com' as never);

    expect((await t.auth.revertEmailChange({ token: revert, meta: meta() })).ok).toBe(true);
    expect((await t.stores.users.findById(userId))?.email).toBe(OWNER);

    await requestAndDrain(t, OWNER);

    const reset = tokenOf(t.mailer.last('password-reset')?.url);

    expect(
      (await t.auth.resetPassword({ token: reset, password: 'the owner again!', meta: meta() })).ok,
    ).toBe(true);
  });

  it('support ends the lockout with clearEmailRevertLockout, audited for review', async () => {
    const { t, userId } = await refusedRevert();

    await t.auth.clearEmailRevertLockout({ userId, meta: meta() });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'email.revert_lockout_cleared',
      userId,
      data: { review: true },
    });

    await requestAndDrain(t, INTRUDER);

    expect(t.mailer.last('password-reset')).toMatchObject({ to: INTRUDER });
  });

  it('the lockout never lapses while the account names the intruder address, and the owner link keeps working', async () => {
    const { t, userId, revert, squatterId } = await refusedRevert();

    t.clock.advance(10 * 365 * 24 * 60 * 60_000);

    const before = t.mailer.sent.length;

    await requestAndDrain(t, INTRUDER);

    expect(t.mailer.sent.slice(before)).toEqual([]);

    expect(await t.auth.context.tokens.findLive('email-revert-lockout', userId)).toMatchObject({
      expiresAt: Date.UTC(9999, 11, 31),
    });

    await t.stores.users.setEmail(squatterId, 'elsewhere@example.com' as never);

    expect((await t.auth.revertEmailChange({ token: revert, meta: meta() })).ok).toBe(true);
    expect(await t.auth.context.tokens.findLive('email-revert-lockout', userId)).toBeNull();
  });

  it('isAddressHeld names a held address, so an app path can refuse it', async () => {
    const t = queued();
    const { session } = await t.signedInUser(OWNER);

    expect(await t.auth.isAddressHeld(OWNER)).toBe(false);

    await changed(t, session, INTRUDER);

    expect(await t.auth.isAddressHeld(' Ada@Example.com ')).toBe(true);
    expect(await t.auth.isAddressHeld(INTRUDER)).toBe(false);
    expect(await t.auth.isAddressHeld('not an address')).toBe(false);
  });
});
