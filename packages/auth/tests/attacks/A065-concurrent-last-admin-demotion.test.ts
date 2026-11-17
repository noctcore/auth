// A061: leaving a scope without an admin by demoting or removing the last two at once.
//
// Two admins demote each other at the same moment, or remove each other, or a
// script fires every demotion of a scope in parallel. Each request checks
// "is another admin left?" before its write, sees one, and writes: the scope
// ends up with no admin, and nobody can manage it any more.
//
// Stopped by: plugins/membership/guards.ts (the last-admin decision is left to the
//   store's guarded write, never decided on an earlier read), ports/membership.ts
//   (`changeRole` and `removeMember` check the other admins and write in one atomic
//   step), src/testing/conformance/membership-store.ts (the race, under concurrency,
//   for every adapter: auth-prisma and auth-redis run it against Postgres and Redis).
// Learn: Build, Membership guards (/auth/build/membership/)
import { describe, expect, it } from 'vitest';

import { acting, membershipApp } from '../membership/setup';

async function admins(t: ReturnType<typeof membershipApp>) {
  const members = await t.store.listMembers('org_1');

  return members.filter((m) => m.role === 'owner' || m.role === 'admin').length;
}

describe('A061: leaving a scope without an admin by demoting or removing the last two at once', () => {
  it('lets one of two admins demoting each other at the same moment through, never both', async () => {
    const t = membershipApp();
    const a = await t.member('admin');
    const b = await t.member('admin');

    const results = await Promise.all([
      t.auth.membership.changeRole({ ...acting(a, b), role: 'member' }),
      t.auth.membership.changeRole({ ...acting(b, a), role: 'member' }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.find((r) => !r.ok)).toMatchObject({ code: 'last_admin' });
    expect(await admins(t)).toBe(1);
  });

  it('lets one of two admins removing each other at the same moment through, never both', async () => {
    const t = membershipApp();
    const a = await t.member('owner');
    const b = await t.member('admin');

    const results = await Promise.all([
      t.auth.membership.remove(acting(a, b)),
      t.auth.membership.remove(acting(b, a)),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.find((r) => !r.ok)).toMatchObject({ code: 'last_admin' });
    expect(await admins(t)).toBe(1);
  });

  it('keeps one admin when a third party fires every demotion and removal in parallel', async () => {
    const t = membershipApp({ canManage: () => true });
    const helper = await t.member('member');
    const targets = await Promise.all([1, 2, 3, 4, 5].map(() => t.member('admin')));

    const results = await Promise.all(
      targets.map((target, i) =>
        i % 2 === 0
          ? t.auth.membership.remove(acting(helper, target))
          : t.auth.membership.changeRole({ ...acting(helper, target), role: 'member' }),
      ),
    );

    expect(results.filter((r) => !r.ok)).toEqual([
      { ok: false, code: 'last_admin', reason: 'last_admin' },
    ]);

    expect(await admins(t)).toBe(1);
  });

  it('refuses to remove or demote the last admin even when asked one at a time', async () => {
    const t = membershipApp({ canManage: () => true });
    const lone = await t.member('owner');
    const other = await t.member('member');

    expect(await t.auth.membership.remove(acting(other, lone))).toMatchObject({
      code: 'last_admin',
    });

    expect(
      await t.auth.membership.changeRole({ ...acting(other, lone), role: 'member' }),
    ).toMatchObject({ code: 'last_admin' });

    expect((await t.store.findMember('org_1', lone.userId))?.role).toBe('owner');
  });
});
