// A070: accepting an invitation with an account at another address.
//
// The link leaks (a forwarded mail, a shared screen, a proxy log) and someone
// signed in as themselves opens it. An invitation that trusts whoever holds
// the token joins the wrong person to the scope.
//
// Stopped by: plugins/invitations/accept.ts (`accept` compares the signed-in
//   account's normalised address with the invited one, which `create` stored
//   normalised, and refuses on any difference without spending the invitation).
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import { invitationApp, meta, SCOPE } from '../invitations/setup';

describe('A070: accepting an invitation with an account at another address', () => {
  it('refuses a holder of the link signed in under another address, and keeps the invitation', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const eve = await t.user({ email: 'eve@example.com' });
    const { token } = await t.invite(inviter, 'bob@example.com');

    expect(await t.auth.invitations.accept({ session: eve.session, token, meta: meta() })).toEqual({
      ok: false,
      code: 'forbidden',
      reason: 'email_mismatch',
    });

    expect(t.onAccept).not.toHaveBeenCalled();
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });

  it('compares normalised addresses, so case and spaces neither block nor pass anyone', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const lookalike = await t.user({ email: 'bob@example.co' });
    const { token } = await t.invite(inviter, '  BOB@Example.COM ');

    expect(
      await t.auth.invitations.accept({ session: lookalike.session, token, meta: meta() }),
    ).toMatchObject({ reason: 'email_mismatch' });

    expect(
      (await t.auth.invitations.accept({ session: bob.session, token, meta: meta() })).ok,
    ).toBe(true);
  });
});
