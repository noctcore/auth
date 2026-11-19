// A096: accepting an invitation without a session (acceptWithoutSession).
//
// With `acceptWithoutSession` an app lets the holder of an invitation link
// accept it with no session: the account that holds the invited address joins.
// An attacker who gets hold of the link tries to turn it into a sign-in, a
// squatter who registered the address first and never verified it tries to
// collect the seat through the owner's link, and on an app that left the
// option off a bare link is tried as if it were on.
//
// Stopped by: plugins/invitations/accept.ts (no session is issued by any
//   accept; an account whose address is not verified is refused and nothing is
//   spent; with the option off a null session is refused before the token is
//   looked up), plugins/invitations/options.ts (the option is off unless set to
//   true).
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import { invitationApp, meta, PASSWORD, SCOPE } from '../invitations/setup';

describe('A096: accepting an invitation without a session', () => {
  it('joins the verified holder of the address but signs nobody in', async () => {
    const t = invitationApp({ acceptWithoutSession: true });
    const inviter = await t.user({ canInvite: true });
    const victim = await t.user({ email: 'victim@example.com' });
    const { token } = await t.invite(inviter, 'victim@example.com');
    const created = () => t.audit.types().filter((type) => type === 'session.created').length;
    const before = created();

    const result = await t.auth.invitations.accept({
      session: null,
      token,
      meta: meta('198.51.100.66'),
    });

    expect(result.ok).toBe(true);
    expect(result).not.toHaveProperty('value.session');
    expect(created()).toBe(before);
    expect(await t.auth.context.sessions.listActive(victim.userId)).toHaveLength(1);
  });

  it("refuses an unverified squatter's account and leaves the invitation for the owner", async () => {
    const t = invitationApp({ acceptWithoutSession: true });
    const inviter = await t.user({ canInvite: true });
    const squatter = await t.user({ email: 'victim@example.com', verified: false });
    const { token } = await t.invite(inviter, 'victim@example.com');

    expect(await t.auth.invitations.accept({ session: null, token, meta: meta() })).toEqual({
      ok: false,
      code: 'forbidden',
      reason: 'email_unverified',
    });

    expect(
      await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'email_in_use' });

    expect((await t.stores.users.findById(squatter.userId))?.emailVerified).toBe(false);
    expect(t.onAccept).not.toHaveBeenCalled();
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });

  it('does nothing with a bare link while the option is off', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    await t.user({ email: 'victim@example.com' });

    const { token } = await t.invite(inviter, 'victim@example.com');

    expect(await t.auth.invitations.accept({ session: null, token, meta: meta() })).toEqual({
      ok: false,
      code: 'forbidden',
      reason: 'session_required',
    });

    expect(t.onAccept).not.toHaveBeenCalled();
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });
});
