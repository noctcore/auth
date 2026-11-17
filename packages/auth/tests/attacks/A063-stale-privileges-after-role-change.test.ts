// A063: keeping a role, or a scope, after it was taken away.
//
// An admin is demoted or removed, but the session they already hold keeps
// working: it carries the old role in its attributes, or it simply stays
// signed in to a scope it no longer belongs to. Or a login racing the change
// reads the old role and mints a fresh session with it just after the change.
//
// Stopped by: plugins/membership/guards.ts (a role change or a removal is followed by
//   `revokeAllSessions`, which bumps the epoch; the write comes first, so a login that
//   starts later reads the new role), session/session-manager.ts (the epoch fence:
//   a login that read the old epoch is refused at mint, and a session stamped with it
//   fails validation).
// Learn: Revocation races and the epoch fence (/auth/learn/revocation-races/); core A006
import { describe, expect, it } from 'vitest';

import { acting, membershipApp, meta, PASSWORD } from '../membership/setup';

describe('A063: keeping a role, or a scope, after it was taken away', () => {
  it('ends the session of a demoted admin, on every device', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const target = await t.member('admin');
    const second = await t.auth.login({ email: target.email, password: PASSWORD, meta: meta() });

    if (!second.ok || second.value.kind !== 'session') throw new Error('login failed');

    await t.auth.membership.changeRole({ ...acting(admin, target), role: 'member' });

    expect(await t.sessionOf(target.token)).toBeNull();
    expect(await t.sessionOf(second.value.session.token)).toBeNull();
  });

  it('ends the session of a removed member', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const target = await t.member('member');

    expect((await t.auth.membership.remove(acting(admin, target))).ok).toBe(true);
    expect(await t.sessionOf(target.token)).toBeNull();
  });

  it('refuses a login that read the old role while the change landed', async () => {
    let race: (() => Promise<unknown>) | null = null;

    const t = membershipApp(
      {},
      {
        // The app's attribute hook reads the role; the demotion lands right after.
        hooks: {
          sessionAttributes: async () => {
            const landing = race;

            race = null;

            if (landing) await landing();

            return {};
          },
        },
      },
    );

    const admin = await t.member('admin');
    const target = await t.member('admin');

    race = () => t.auth.membership.changeRole({ ...acting(admin, target), role: 'member' });

    const login = await t.auth.login({ email: target.email, password: PASSWORD, meta: meta() });

    expect(login).toMatchObject({ ok: false, code: 'session_expired', reason: 'epoch_fence' });
    expect((await t.store.findMember('org_1', target.userId))?.role).toBe('member');
    expect(await t.stores.sessions.listByUser(target.userId)).toEqual([]);

    // A login that starts after the change gets a session, under the new role.
    const after = await t.auth.login({ email: target.email, password: PASSWORD, meta: meta() });

    expect(after.ok).toBe(true);
  });
});
