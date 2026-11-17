/**
 * UserStore conformance: unique violations returned as null, guarded writes
 * refusing deleted users and, for a store with `changeEmail`, an address
 * change that is a compare-and-set and keeps the address unique.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';
import type { UserStore } from '../../ports/stores';
import type { NormalizedEmail } from '../../shared/email';
import { times, uniqueId, type ConformanceCase } from '../harness';

export interface UserStoreConformanceOptions {
  /** Soft-deletes a user, if the adapter supports soft deletion. */
  readonly softDelete?: (id: string) => Promise<void>;
}

export function userStoreConformance(
  store: UserStore,
  options: UserStoreConformanceOptions = {},
): ConformanceCase[] {
  const email = () => `${uniqueId('person')}@example.com` as NormalizedEmail;

  const cases: ConformanceCase[] = [
    {
      name: 'creates a user and finds it with and without its credential',
      async run() {
        const address = email();
        const user = await store.create({ email: address, passwordHash: 'hash-1' });

        assert.ok(user);
        assert.equal(user.email, address);
        assert.equal(user.emailVerified, false);
        assert.deepEqual(await store.findById(user.id), user);
        assert.equal((await store.findCredentialByEmail(address))?.passwordHash, 'hash-1');
        assert.equal((await store.findCredentialById(user.id))?.passwordHash, 'hash-1');
        assert.equal(await store.findCredentialByEmail(email()), null);
        assert.equal(await store.findById(uniqueId('missing')), null);
      },
    },
    {
      name: 'returns null for a taken email, even under 20 concurrent creates',
      async run() {
        const address = email();

        assert.ok(await store.create({ email: address, passwordHash: 'h' }));
        assert.equal(await store.create({ email: address, passwordHash: 'h' }), null);
        const raced = email();
        const results = await times(20, () => store.create({ email: raced, passwordHash: 'h' }));

        assert.equal(results.filter(Boolean).length, 1);
      },
    },
    {
      name: 'sets a password hash only on an existing user',
      async run() {
        const user = await store.create({ email: email(), passwordHash: 'old' });

        assert.ok(user);
        assert.equal(await store.setPasswordHash(user.id, 'new'), true);
        assert.equal((await store.findCredentialById(user.id))?.passwordHash, 'new');
        assert.equal(await store.setPasswordHash(uniqueId('missing'), 'x'), false);
      },
    },
    {
      name: 'compare-and-set writes only while the hash is still the expected one, even under concurrency',
      async run() {
        const user = await store.create({ email: email(), passwordHash: 'v1' });

        assert.ok(user);
        assert.equal(await store.setPasswordHash(user.id, 'v2', { expected: 'stale' }), false);
        assert.equal((await store.findCredentialById(user.id))?.passwordHash, 'v1');

        const results = await times(10, (i) =>
          store.setPasswordHash(user.id, `next-${i}`, { expected: 'v1' }),
        );

        assert.equal(results.filter(Boolean).length, 1, 'exactly one compare-and-set may win');
      },
    },
    {
      name: 'marks the email verified only while it is still the same address',
      async run() {
        const address = email();
        const user = await store.create({ email: address, passwordHash: 'h' });

        assert.ok(user);
        assert.equal(await store.markEmailVerified(user.id, email()), false);
        assert.equal((await store.findById(user.id))?.emailVerified, false);
        assert.equal(await store.markEmailVerified(user.id, address), true);
        assert.equal((await store.findById(user.id))?.emailVerified, true);
      },
    },
  ];

  const changeEmail = store.changeEmail?.bind(store);

  if (changeEmail) {
    cases.push(
      {
        name: 'changes the email only from the expected address, marks it verified and can clear the password',
        async run() {
          const from = email();
          const user = await store.create({ email: from, passwordHash: 'h' });

          assert.ok(user);
          assert.equal(await changeEmail(user.id, { from: email(), to: email() }), 'stale');
          assert.equal(await changeEmail(uniqueId('missing'), { from, to: email() }), 'stale');

          const to = email();

          assert.equal(await changeEmail(user.id, { from, to }), 'changed');

          assert.deepEqual(await store.findById(user.id), {
            ...user,
            email: to,
            emailVerified: true,
          });

          assert.equal(await store.findCredentialByEmail(from), null);
          assert.equal((await store.findCredentialByEmail(to))?.passwordHash, 'h');
          assert.equal(await changeEmail(user.id, { from, to: email() }), 'stale');

          const back = email();

          assert.equal(
            await changeEmail(user.id, { from: to, to: back, clearPassword: true }),
            'changed',
          );

          assert.equal((await store.findCredentialById(user.id))?.passwordHash, null);
        },
      },
      {
        name: 'refuses a taken address as taken, and of 10 users racing for one address exactly one gets it',
        async run() {
          const taken = email();

          assert.ok(await store.create({ email: taken, passwordHash: 'h' }));
          const from = email();
          const user = await store.create({ email: from, passwordHash: 'h' });

          assert.ok(user);
          assert.equal(await changeEmail(user.id, { from, to: taken }), 'taken');
          assert.equal((await store.findById(user.id))?.email, from);

          const racers = await times(10, async () => {
            const address = email();
            const racer = await store.create({ email: address, passwordHash: 'h' });

            assert.ok(racer);

            return { id: racer.id, address };
          });

          const target = email();

          const results = await Promise.all(
            racers.map((r) => changeEmail(r.id, { from: r.address, to: target })),
          );

          assert.equal(results.filter((r) => r === 'changed').length, 1, 'exactly one may win');
          assert.equal(results.filter((r) => r === 'taken').length, 9);
        },
      },
    );
  }

  const softDelete = options.softDelete;

  if (softDelete) {
    cases.push({
      name: 'a soft-deleted user is not found and its guarded writes are refused',
      async run() {
        const address = email();
        const user = await store.create({ email: address, passwordHash: 'h' });

        assert.ok(user);
        await softDelete(user.id);
        assert.equal(await store.findCredentialByEmail(address), null);
        assert.equal(await store.findById(user.id), null);
        assert.equal(await store.setPasswordHash(user.id, 'new'), false);
        assert.equal(await store.markEmailVerified(user.id, address), false);

        if (changeEmail)
          assert.equal(await changeEmail(user.id, { from: address, to: email() }), 'stale');
      },
    });
  }

  return cases;
}
