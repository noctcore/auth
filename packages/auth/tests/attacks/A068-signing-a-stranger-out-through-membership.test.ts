// A068: signing a stranger out of everything through the membership flows.
//
// Any user creates a scope of their own, adds the victim by user id (no consent
// is asked), then sets the victim's role to the one they already hold, or
// removes them again. If each of those revokes the victim's sessions, and the
// epoch is per user, the victim is signed out on every device and in every
// scope, and loses their trusted devices, as often as the attacker likes.
//
// Stopped by: plugins/membership/guards.ts (no session is revoked unless the app
//   turns on `revokeSessionsOnChange`; even then adding never revokes, and setting
//   the role a member already holds is a no-op that revokes nothing);
//   plugins/membership/options.ts (revocation is off by default: the guards read roles
//   from the store on every call and never need it).
// Not stopped: with `revokeSessionsOnChange` on, an admin of any scope the victim
//   belongs to can sign them out by a role change or a removal, even one the store
//   then refuses (the first revocation runs before the write). So with the option on,
//   this attack is stopped only where adding a member needs the user's consent:
//   adding without consent is app policy; the invitations plugin is the consent path.
// Learn: Build, Membership guards (/auth/build/membership/)
import { describe, expect, it } from 'vitest';

import { acting, membershipApp } from '../membership/setup';

describe('A068: signing a stranger out of everything through the membership flows', () => {
  it('keeps the victim signed in through add, a same-role change and a removal, by default', async () => {
    const t = membershipApp();
    const attacker = await t.member('owner', 'attacker_org');
    const victim = await t.member('owner', 'victim_org');
    const act = acting(attacker, victim, 'attacker_org');

    for (let round = 0; round < 3; round++) {
      expect((await t.auth.membership.add({ ...act, role: 'member' })).ok).toBe(true);
      expect((await t.auth.membership.changeRole({ ...act, role: 'member' })).ok).toBe(true);
      expect((await t.auth.membership.changeRole({ ...act, role: 'admin' })).ok).toBe(true);
      expect((await t.auth.membership.remove(act)).ok).toBe(true);
    }

    expect(await t.sessionOf(victim.token)).not.toBeNull();
    expect(t.audit.types()).not.toContain('sessions.revoked');
  });

  it('with revocation on, never revokes on an add or a same-role change', async () => {
    const t = membershipApp({ revokeSessionsOnChange: true });
    const attacker = await t.member('owner', 'attacker_org');
    const victim = await t.member('owner', 'victim_org');
    const act = acting(attacker, victim, 'attacker_org');

    expect((await t.auth.membership.add({ ...act, role: 'member' })).ok).toBe(true);
    expect((await t.auth.membership.changeRole({ ...act, role: 'member' })).ok).toBe(true);
    expect(await t.sessionOf(victim.token)).not.toBeNull();
  });
});
