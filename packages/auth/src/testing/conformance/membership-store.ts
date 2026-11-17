/**
 * MembershipStore conformance: the properties the membership plugin relies
 * on. A guarded write applies only to the role it was decided on, never leaves
 * a scope without an admin, and stays that way under concurrency: two admins
 * demoting or removing each other at the same moment leave one admin, not
 * none.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';
import type { MembershipStore, MemberWrite } from '../../ports/membership';
import { times, uniqueId, type ConformanceCase } from '../harness';

const ADMINS = ['owner', 'admin'] as const;

/** A fresh scope with the given members, as `userId -> role`; returns the scope and the user ids. */
async function scopeWith(
  store: MembershipStore,
  roles: readonly string[],
): Promise<{ scope: string; users: string[] }> {
  const scope = uniqueId('scope');
  const users = roles.map(() => uniqueId('user'));

  for (const [index, role] of roles.entries())
    assert.equal(await store.addMember({ scope, userId: users[index] ?? '', role }), true);

  return { scope, users };
}

function demote(store: MembershipStore, scope: string, userId: string): Promise<MemberWrite> {
  return store.changeRole({ scope, userId, from: 'admin', to: 'member', adminRoles: ADMINS });
}

function remove(store: MembershipStore, scope: string, userId: string): Promise<MemberWrite> {
  return store.removeMember({ scope, userId, from: 'admin', adminRoles: ADMINS });
}

async function adminCount(store: MembershipStore, scope: string): Promise<number> {
  const members = await store.listMembers(scope);

  return members.filter((m) => (ADMINS as readonly string[]).includes(m.role)).length;
}

export function membershipStoreConformance(store: MembershipStore): ConformanceCase[] {
  return [
    {
      name: 'adds a member once, and finds and lists it',
      async run() {
        const scope = uniqueId('scope');
        const userId = uniqueId('user');

        assert.equal(await store.findMember(scope, userId), null);
        assert.deepEqual(await store.listMembers(scope), []);
        assert.equal(await store.addMember({ scope, userId, role: 'member' }), true);
        assert.equal(await store.addMember({ scope, userId, role: 'admin' }), false);
        assert.deepEqual(await store.findMember(scope, userId), { scope, userId, role: 'member' });
        assert.deepEqual(await store.listMembers(scope), [{ scope, userId, role: 'member' }]);
        assert.equal(await store.findMember(uniqueId('scope'), userId), null);
      },
    },
    {
      name: 'adds a user to one scope without touching another',
      async run() {
        const userId = uniqueId('user');
        const [first, second] = [uniqueId('scope'), uniqueId('scope')];

        await store.addMember({ scope: first, userId, role: 'admin' });
        await store.addMember({ scope: second, userId, role: 'member' });
        assert.equal((await store.findMember(first, userId))?.role, 'admin');
        assert.equal((await store.findMember(second, userId))?.role, 'member');
      },
    },
    {
      name: 'changes a role only from the role the caller decided on',
      async run() {
        const { scope, users } = await scopeWith(store, ['owner', 'member']);
        const [, userId = ''] = users;

        const change = (from: string, to: string) =>
          store.changeRole({ scope, userId, from, to, adminRoles: ADMINS });

        assert.equal(await change('admin', 'viewer'), 'stale');
        assert.equal((await store.findMember(scope, userId))?.role, 'member');
        assert.equal(await change('member', 'admin'), 'done');
        assert.equal((await store.findMember(scope, userId))?.role, 'admin');

        assert.equal(
          await store.changeRole({
            scope,
            userId: uniqueId('nobody'),
            from: 'member',
            to: 'admin',
            adminRoles: ADMINS,
          }),
          'missing',
        );
      },
    },
    {
      name: 'refuses to demote the last admin, and allows it while another admin remains',
      async run() {
        const { scope, users } = await scopeWith(store, ['admin', 'member']);
        const [admin = '', member = ''] = users;

        assert.equal(await demote(store, scope, admin), 'last_admin');
        assert.equal((await store.findMember(scope, admin))?.role, 'admin');

        // From one admin role to another keeps an admin.
        assert.equal(
          await store.changeRole({
            scope,
            userId: admin,
            from: 'admin',
            to: 'owner',
            adminRoles: ADMINS,
          }),
          'done',
        );

        await store.changeRole({
          scope,
          userId: member,
          from: 'member',
          to: 'admin',
          adminRoles: ADMINS,
        });

        assert.equal(await demote(store, scope, member), 'done');
        assert.equal(await adminCount(store, scope), 1);
      },
    },
    {
      name: 'refuses to remove the last admin, and removes other members',
      async run() {
        const { scope, users } = await scopeWith(store, ['admin', 'member']);
        const [admin = '', member = ''] = users;

        assert.equal(await remove(store, scope, admin), 'last_admin');
        assert.equal(await remove(store, scope, member), 'stale');

        assert.equal(
          await store.removeMember({ scope, userId: member, from: 'member', adminRoles: ADMINS }),
          'done',
        );

        assert.equal(await store.findMember(scope, member), null);
        assert.equal(await remove(store, scope, member), 'missing');
        assert.equal((await store.findMember(scope, admin)) !== null, true);
      },
    },
    {
      name: 'counts only the admins of the same scope',
      async run() {
        const { scope, users } = await scopeWith(store, ['admin']);
        const [admin = ''] = users;
        const elsewhere = uniqueId('scope');

        await store.addMember({ scope: elsewhere, userId: uniqueId('user'), role: 'admin' });
        await store.addMember({ scope: elsewhere, userId: admin, role: 'admin' });

        assert.equal(await demote(store, scope, admin), 'last_admin');
        assert.equal(await remove(store, scope, admin), 'last_admin');
      },
    },
    {
      name: 'leaves one admin when two admins demote each other at the same moment',
      async run() {
        for (let round = 0; round < 10; round++) {
          const { scope, users } = await scopeWith(store, ['admin', 'admin']);
          const results = await Promise.all(users.map((userId) => demote(store, scope, userId)));

          assert.deepEqual([...results].sort(), ['done', 'last_admin']);
          assert.equal(await adminCount(store, scope), 1);
        }
      },
    },
    {
      name: 'leaves one admin when two admins remove each other at the same moment',
      async run() {
        for (let round = 0; round < 10; round++) {
          const { scope, users } = await scopeWith(store, ['admin', 'admin']);
          const results = await Promise.all(users.map((userId) => remove(store, scope, userId)));

          assert.deepEqual([...results].sort(), ['done', 'last_admin']);
          assert.equal(await adminCount(store, scope), 1);
        }
      },
    },
    {
      name: 'leaves exactly one admin when every admin is demoted or removed at once',
      async run() {
        const { scope, users } = await scopeWith(store, Array<string>(8).fill('admin'));

        const results = await Promise.all(
          users.map((userId, index) =>
            index % 2 === 0 ? demote(store, scope, userId) : remove(store, scope, userId),
          ),
        );

        assert.equal(results.filter((r) => r === 'done').length, users.length - 1);
        assert.equal(results.filter((r) => r === 'last_admin').length, 1);
        assert.equal(await adminCount(store, scope), 1);
      },
    },
    {
      name: 'adds a member once when many callers add it at the same moment',
      async run() {
        const scope = uniqueId('scope');
        const userId = uniqueId('user');

        const added = await times(10, (i) =>
          store.addMember({ scope, userId, role: i === 0 ? 'admin' : 'member' }),
        );

        assert.equal(added.filter(Boolean).length, 1);
        assert.equal((await store.listMembers(scope)).length, 1);
      },
    },
  ];
}
