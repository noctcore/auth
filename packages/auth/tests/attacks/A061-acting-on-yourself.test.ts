// A061: acting on yourself through the membership flows.
//
// A member promotes themselves to admin, or the last admin demotes or removes
// themselves by mistake, or a member adds themselves to a scope they do not
// belong to. An app that checks "is the actor an admin?" but not "is the actor
// the target?" lets every one of them through.
//
// Stopped by: plugins/membership/guards.ts (every flow refuses `self_target` when the
//   session's user id equals the target id, before any lookup; ids are compared, never
//   emails, so a second spelling of an address cannot pass for another person; the
//   actor's role comes from the store, never from the session).
// Learn: Build, Membership guards (/auth/build/membership/)
import { describe, expect, it } from 'vitest';

import { acting, membershipApp } from '../membership/setup';

describe('A061: acting on yourself through the membership flows', () => {
  it('refuses self-promotion, even when the app allows every actor', async () => {
    const t = membershipApp({ canManage: () => true });
    const member = await t.member('member');

    const promoted = await t.auth.membership.changeRole({
      ...acting(member, member),
      role: 'owner',
    });

    expect(promoted).toEqual({ ok: false, code: 'self_target', reason: 'self_target' });
    expect((await t.store.findMember('org_1', member.userId))?.role).toBe('member');
  });

  it('refuses an admin demoting or removing themselves, and keeps the session', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');

    await t.member('admin');

    expect(
      await t.auth.membership.changeRole({ ...acting(admin, admin), role: 'member' }),
    ).toMatchObject({ code: 'self_target' });

    expect(await t.auth.membership.remove(acting(admin, admin))).toMatchObject({
      code: 'self_target',
    });

    expect((await t.store.findMember('org_1', admin.userId))?.role).toBe('admin');
    expect(await t.sessionOf(admin.token)).not.toBeNull();
  });

  it('refuses a user adding themselves to a scope', async () => {
    const t = membershipApp({ canManage: () => true });
    const outsider = await t.member('admin', 'org_2');

    expect(
      await t.auth.membership.add({ ...acting(outsider, outsider), role: 'owner' }),
    ).toMatchObject({ code: 'self_target' });

    expect(await t.store.findMember('org_1', outsider.userId)).toBeNull();
  });

  it('decides on the role in the store, not on what the session claims', async () => {
    const t = membershipApp();
    const member = await t.member('member');
    const target = await t.member('member');
    const claimed = { ...member.session, attributes: { role: 'owner' } as never };

    expect(
      await t.auth.membership.changeRole({
        ...acting({ session: claimed }, target),
        role: 'admin',
      }),
    ).toMatchObject({ code: 'forbidden', reason: 'not_allowed' });
  });
});
