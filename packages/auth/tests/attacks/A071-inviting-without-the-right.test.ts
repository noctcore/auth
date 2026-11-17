// A071: inviting without the right, or accepting after the inviter lost it.
//
// A plugin that lets any signed-in user invite lets anyone into any
// organisation. And an invitation sent by an admin who was then demoted, or
// whose account was taken over and cleaned up, still opens the door later with
// the privileges the inviter no longer has.
//
// Stopped by: plugins/invitations/options.ts (no `authorize`, no plugin: it cannot be
//   wired open); plugins/invitations/manage.ts (create, list and revoke ask
//   `authorize` with the user read from the store); plugins/invitations/accept.ts
//   (the inviter is checked again on accept, and the invitation withdrawn when they
//   no longer pass); plugins/invitations/index.ts (revoking all of the inviter's
//   sessions deletes their pending invitations).
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import { invitations } from '../../src/plugins/invitations';
import { MemoryInvitationStore } from '../../src/testing';
import { invitationApp, meta, SCOPE } from '../invitations/setup';

describe('A071: inviting without the right, or accepting after the inviter lost it', () => {
  it('refuses to start without a permission check', () => {
    expect(() =>
      invitations({
        store: new MemoryInvitationStore(),
        authorize: undefined as never,
        onAccept: () => undefined,
        url: (token) => `https://app.example/invite#${token}`,
      }),
    ).toThrow('invitations: authorize is required, so creating is never open');
  });

  it('refuses a user the app does not allow, and sends nothing', async () => {
    const t = invitationApp();
    const member = await t.user();

    expect(
      await t.auth.invitations.create({
        session: member.session,
        scope: SCOPE,
        email: 'friend@example.com',
        meta: meta(),
      }),
    ).toEqual({ ok: false, code: 'forbidden', reason: 'not_allowed' });

    expect(t.mailer.last('invitation')).toBeUndefined();
  });

  it('withdraws an invitation whose inviter was demoted before it was accepted', async () => {
    const t = invitationApp();
    const admin = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(admin, bob.email);

    t.allowed.delete(admin.userId);

    expect(await t.auth.invitations.accept({ session: bob.session, token, meta: meta() })).toEqual({
      ok: false,
      code: 'invalid_token',
      reason: 'inviter_not_allowed',
    });

    t.allowed.add(admin.userId);

    expect(
      await t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).toMatchObject({ reason: 'unknown_token' });

    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it("deletes the inviter's pending invitations when all their sessions are revoked", async () => {
    const t = invitationApp();
    const admin = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(admin, bob.email);

    await t.auth.context.revokeAllSessions(admin.userId, 'revoke-all');

    expect(
      await t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'unknown_token' });
  });
});
