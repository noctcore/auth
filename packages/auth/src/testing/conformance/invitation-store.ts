/**
 * InvitationStore conformance: the properties the invitations plugin relies
 * on. An invitation is spent exactly once, even by many concurrent accepts,
 * one scope and address hold at most one live invitation, also under
 * concurrent creates, and revoking or spending one frees the address again.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';
import { systemClock } from '../../ports/clock';
import type { InvitationStore, StoredInvitation } from '../../ports/invitations';
import {
  advance,
  times,
  uniqueId,
  type ConformanceCase,
  type ConformanceContext,
} from '../harness';

function invitation(overrides: Partial<StoredInvitation> = {}): StoredInvitation {
  const now = systemClock.now();

  return {
    id: uniqueId('inv'),
    hash: uniqueId('hash'),
    scope: uniqueId('scope'),
    email: `${uniqueId('user')}@example.com`,
    inviterId: uniqueId('inviter'),
    payload: { role: 'member' },
    createdAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

export function invitationStoreConformance(
  store: InvitationStore,
  context: ConformanceContext = {},
): ConformanceCase[] {
  const wait = advance(context);

  return [
    {
      name: 'creates an invitation, finds it by hash and lists it in its scope only',
      async run() {
        const stored = invitation();

        assert.equal(await store.findByHash(stored.hash), null);
        assert.equal(await store.create(stored, stored.createdAt), true);
        assert.deepEqual(await store.findByHash(stored.hash), stored);
        assert.deepEqual(await store.listByScope(stored.scope, stored.createdAt), [stored]);
        assert.deepEqual(await store.listByScope(uniqueId('scope'), stored.createdAt), []);
      },
    },
    {
      name: 'refuses a second live invitation for the same scope and address, not for another scope',
      async run() {
        const first = invitation();
        const again = invitation({ scope: first.scope, email: first.email });
        const elsewhere = invitation({ email: first.email });

        assert.equal(await store.create(first, first.createdAt), true);
        assert.equal(await store.create(again, first.createdAt), false);
        assert.equal(await store.findByHash(again.hash), null);
        assert.equal(await store.create(elsewhere, first.createdAt), true);
      },
    },
    {
      name: 'replaces an expired invitation for the same scope and address, and lists only live ones',
      async run() {
        const now = systemClock.now();
        const old = invitation({ createdAt: now, expiresAt: now + 100 });
        const fresh = invitation({ scope: old.scope, email: old.email, expiresAt: now + 60_000 });

        assert.equal(await store.create(old, now), true);
        assert.deepEqual(await store.listByScope(old.scope, old.expiresAt), []);
        await wait(150);
        assert.equal(await store.create(fresh, old.expiresAt + 1), true);
        assert.deepEqual(await store.listByScope(old.scope, old.expiresAt + 1), [fresh]);
      },
    },
    {
      name: 'consumes an invitation once, and frees its address for a new one',
      async run() {
        const stored = invitation();

        await store.create(stored, stored.createdAt);
        assert.deepEqual(await store.consume(stored.hash), stored);
        assert.equal(await store.consume(stored.hash), null);
        assert.equal(await store.findByHash(stored.hash), null);
        assert.deepEqual(await store.listByScope(stored.scope, stored.createdAt), []);

        const next = invitation({ scope: stored.scope, email: stored.email });

        assert.equal(await store.create(next, stored.createdAt), true);
      },
    },
    {
      name: 'gives an invitation to exactly one of many concurrent consumers',
      async run() {
        const stored = invitation();

        await store.create(stored, stored.createdAt);

        const results = await times(20, () => store.consume(stored.hash));

        assert.equal(results.filter((r) => r !== null).length, 1);
      },
    },
    {
      name: 'creates at most one of many concurrent invitations for one scope and address',
      async run() {
        const first = invitation();

        const all = Array.from({ length: 10 }, () =>
          invitation({ scope: first.scope, email: first.email }),
        );

        const created = await Promise.all(all.map((i) => store.create(i, first.createdAt)));

        assert.equal(created.filter(Boolean).length, 1);
        assert.equal((await store.listByScope(first.scope, first.createdAt)).length, 1);
      },
    },
    {
      name: 'revokes an invitation by id only within its own scope',
      async run() {
        const stored = invitation();

        await store.create(stored, stored.createdAt);
        assert.equal(await store.revoke(uniqueId('scope'), stored.id), false);
        assert.equal(await store.revoke(stored.scope, uniqueId('inv')), false);
        assert.equal(await store.revoke(stored.scope, stored.id), true);
        assert.equal(await store.findByHash(stored.hash), null);
        assert.equal(await store.revoke(stored.scope, stored.id), false);

        const next = invitation({ scope: stored.scope, email: stored.email });

        assert.equal(await store.create(next, stored.createdAt), true);
      },
    },
    {
      name: "deletes every invitation of one inviter and nobody else's",
      async run() {
        const inviterId = uniqueId('inviter');
        const first = invitation({ inviterId });
        const mine = [first, invitation({ inviterId })];
        const theirs = invitation();

        for (const stored of [...mine, theirs]) await store.create(stored, stored.createdAt);

        await store.deleteByInviter(inviterId);

        for (const stored of mine) assert.equal(await store.findByHash(stored.hash), null);

        assert.deepEqual(await store.findByHash(theirs.hash), theirs);

        const again = invitation({ scope: first.scope, email: first.email });

        assert.equal(await store.create(again, again.createdAt), true);
      },
    },
  ];
}
