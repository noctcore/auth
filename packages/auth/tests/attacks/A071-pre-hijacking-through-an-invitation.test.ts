// A071: collecting an invitation with an unverified account (pre-hijacking).
//
// An attacker registers the victim's address before the victim ever signs up,
// never verifies it, and waits. When an organisation invites the victim, an
// invitation that attaches to "the account with that address" hands the
// attacker the seat, and the victim later inherits an account the attacker
// still holds a password for.
//
// Stopped by: plugins/invitations/accept.ts (`accept` refuses an account whose
//   address is not verified and spends nothing; `register` refuses an address that
//   already has an account, so the token never verifies or joins it, and marks the
//   address verified only on an account it created itself).
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import { invitationApp, meta, PASSWORD, SCOPE } from '../invitations/setup';

describe('A071: collecting an invitation with an unverified account (pre-hijacking)', () => {
  it('refuses the unverified squatter on accept, and the token never verifies it', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const squatter = await t.user({ email: 'victim@example.com', verified: false });
    const { token } = await t.invite(inviter, 'victim@example.com');

    expect(
      await t.auth.invitations.accept({ session: squatter.session, token, meta: meta() }),
    ).toEqual({ ok: false, code: 'forbidden', reason: 'email_unverified' });

    expect(
      await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'email_in_use' });

    const account = await t.stores.users.findById(squatter.userId);

    expect(account?.emailVerified).toBe(false);
    expect(t.onAccept).not.toHaveBeenCalled();
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });
});
