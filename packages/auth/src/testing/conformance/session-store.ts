/**
 * SessionStore conformance: no session resurrection after a revocation, the
 * epoch fence, and every record expiring with its session.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';
import { cryptoRandom } from '../../crypto/random';
import { systemClock } from '../../ports/clock';
import { silentLogger } from '../../ports/logger';
import type { SessionStore, StoredSession } from '../../ports/stores';
import { SessionManager } from '../../session/session-manager';
import {
  advance,
  times,
  uniqueId,
  type ConformanceCase,
  type ConformanceContext,
} from '../harness';

function sampleSession(overrides: Partial<StoredSession> = {}): StoredSession {
  const now = systemClock.now();

  return {
    id: uniqueId('sid'),
    userId: uniqueId('user'),
    createdAt: now,
    authenticatedAt: now,
    lastActiveAt: now,
    expiresAt: now + 60_000,
    idleTimeoutMs: 30 * 60_000,
    epoch: 0,
    rememberMe: false,
    persistentCookie: false,
    ip: '203.0.113.7',
    userAgent: 'conformance',
    attributes: { role: 'member', tenantId: 'tenant_1' },
    ...overrides,
  };
}

export interface SessionStoreConformanceOptions extends ConformanceContext {
  /**
   * A second instance of the store on its own connection. With it, the
   * touch-versus-delete race runs across two connections, as it does in
   * production; without it, both calls share one connection.
   */
  readonly secondary?: SessionStore;
  /** Remaining TTL of the user's epoch in ms, for stores that expire it. Enables the epoch TTL check. */
  readonly epochTtlMs?: (userId: string) => Promise<number>;
  /**
   * Whether `delete` returns the ids it removed. Default true, and a store
   * that returns nothing then fails the delete cases with a message naming
   * this option. Pass false for a store that cannot tell: those cases are
   * listed as skipped, and racing evictions may report a session twice.
   */
  readonly deleteReportsRemoved?: boolean;
}

const SKIPPED_DELETE_CASES = ' (skipped: deleteReportsRemoved is false)';

/** The ids a delete reported, or a failure naming the option when it reported nothing. */
function reported(removed: void | readonly string[]): readonly string[] {
  assert.ok(
    Array.isArray(removed),
    'delete returned nothing: return the ids it removed, or pass deleteReportsRemoved: false',
  );

  return removed as readonly string[];
}

export function sessionStoreConformance(
  store: SessionStore,
  context: SessionStoreConformanceOptions = {},
): ConformanceCase[] {
  const cases = [
    ...sessionCases(store, context),
    ...deleteReportCases(store, context.secondary ?? store, context),
  ];

  const epochTtlMs = context.epochTtlMs;

  if (epochTtlMs) {
    cases.push({
      name: 'the epoch outlives the longest session it guards',
      async run() {
        const longest = 30 * 24 * 3600_000;
        const session = sampleSession({ expiresAt: systemClock.now() + longest });

        await store.bumpEpoch(session.userId);
        await store.create({ ...session, epoch: 1 }, longest);

        assert.ok(
          (await epochTtlMs(session.userId)) >= longest,
          'epoch TTL shorter than the session TTL',
        );
      },
    });

    const declared = store.epochTtlMs;

    if (declared !== undefined) {
      cases.push({
        name: 'a bump keeps the epoch for the epochTtlMs the store declares',
        async run() {
          const userId = sampleSession().userId;

          await store.bumpEpoch(userId);

          const remaining = await epochTtlMs(userId);

          // A minute of slack for a slow round trip; never longer than declared.
          assert.ok(
            remaining > declared - 60_000 && remaining <= declared,
            `epoch kept ${remaining} ms, but the store declares epochTtlMs ${declared}`,
          );
        },
      });
    }
  }

  return cases;
}

function sessionCases(
  store: SessionStore,
  context: SessionStoreConformanceOptions,
): ConformanceCase[] {
  const wait = advance(context);
  const other = context.secondary ?? store;

  return [
    {
      name: 'stores and returns a session exactly',
      async run() {
        const session = sampleSession();

        await store.create(session, 60_000);
        assert.deepEqual(await store.get(session.id), session);
        assert.equal(await store.get(uniqueId('missing')), null);
      },
    },
    {
      name: 'expires a session at its TTL',
      async run() {
        const session = sampleSession();

        await store.create(session, 1000);
        await wait(1500);
        assert.equal(await store.get(session.id), null);
        assert.deepEqual(await store.listByUser(session.userId), []);
      },
    },
    {
      name: 'touch replaces the value and keeps the TTL',
      async run() {
        const session = sampleSession();

        await store.create(session, 2000);
        await wait(1000);
        const touched = { ...session, lastActiveAt: session.lastActiveAt + 1000 };

        assert.equal(await store.touch(touched), true);
        assert.deepEqual(await store.get(session.id), touched);
        await wait(1500);
        assert.equal(await store.get(session.id), null, 'touch must not extend the TTL');
      },
    },
    {
      name: 'touch never resurrects a deleted or unknown session',
      async run() {
        const session = sampleSession();

        await store.create(session, 60_000);
        await store.delete(session.userId, [session.id]);
        assert.equal(await store.touch(session), false);
        assert.equal(await store.get(session.id), null);
        const never = sampleSession();

        assert.equal(await store.touch(never), false);
        assert.equal(await store.get(never.id), null);
      },
    },
    {
      name: 'touch racing a delete never leaves the session alive',
      async run() {
        for (let i = 0; i < 40; i++) {
          const session = sampleSession();

          await store.create(session, 60_000);
          const remove = () => store.delete(session.userId, [session.id]);
          const touch = () => other.touch({ ...session, lastActiveAt: session.lastActiveAt + 1 });

          // Alternate which call starts first; on two connections either may land first.
          await Promise.all(i % 2 === 0 ? [remove(), touch()] : [touch(), remove()]);
          assert.equal(await store.get(session.id), null, `iteration ${i}`);
          assert.equal(await other.get(session.id), null, `iteration ${i}, second connection`);
        }
      },
    },
    {
      name: 'a login racing revoke-all never leaves a live session on an old epoch',
      async run() {
        for (let i = 0; i < 25; i++) {
          const manager = new SessionManager(store, {}, systemClock, cryptoRandom, silentLogger);

          const otherManager = new SessionManager(
            other,
            {},
            systemClock,
            cryptoRandom,
            silentLogger,
          );

          const userId = uniqueId('user');
          const meta = { ip: '203.0.113.7' };

          // The login reads the epoch first, as the flows do, then mints.
          const login = async () => {
            const epoch = await manager.readEpoch(userId);

            return manager.mint({
              userId,
              attributes: {},
              rememberMe: false,
              persistentCookie: false,
              authenticatedAt: systemClock.now(),
              epoch,
              meta,
            });
          };

          const [minted] = await Promise.all([login(), otherManager.revokeAll(userId)]);
          const current = await store.getEpoch(userId);

          for (const session of await store.listByUser(userId)) {
            assert.equal(
              session.epoch,
              current,
              `iteration ${i}: a session on epoch ${session.epoch} survived epoch ${current}`,
            );
          }

          if (minted.ok) {
            const validated = await manager.validate(minted.token, { touch: false });

            assert.equal(validated.ok, minted.session.epoch === current, `iteration ${i}`);
          }
        }
      },
    },
    {
      name: 'a mint at the per-user cap keeps the session it just wrote when creation times tie',
      async run() {
        for (let i = 0; i < 10; i++) {
          // One instant for both mints. The older session is the remember-me
          // one on even iterations, so a store that lists by expiry puts the
          // new session first.
          const instant = systemClock.now();
          const frozen = { now: () => instant };

          const manager = new SessionManager(
            store,
            { maxPerUser: 1 },
            frozen,
            cryptoRandom,
            silentLogger,
          );

          const userId = uniqueId('user');

          const mint = (rememberMe: boolean) =>
            manager.mint({
              userId,
              attributes: {},
              rememberMe,
              persistentCookie: false,
              authenticatedAt: instant,
              meta: { ip: '203.0.113.7' },
            });

          const older = await mint(i % 2 === 0);
          const newer = await mint(i % 2 !== 0);

          assert.ok(older.ok && newer.ok, `iteration ${i}: mint refused`);

          assert.ok(
            !newer.evicted.includes(newer.session.id),
            `iteration ${i}: the mint evicted its own session`,
          );

          assert.deepEqual(
            (await store.listByUser(userId)).map((s) => s.id),
            [newer.session.id],
            `iteration ${i}`,
          );

          assert.equal((await manager.validate(newer.token, { touch: false })).ok, true);
        }
      },
    },
    {
      name: 'lists only the live sessions of that user, and delete removes them',
      async run() {
        const userId = uniqueId('user');
        const a = sampleSession({ userId });
        const b = sampleSession({ userId });
        const other = sampleSession();

        await Promise.all([
          store.create(a, 60_000),
          store.create(b, 60_000),
          store.create(other, 60_000),
        ]);

        const ids = (await store.listByUser(userId)).map((s) => s.id).sort();

        assert.deepEqual(ids, [a.id, b.id].sort());
        await store.delete(userId, [a.id]);

        assert.deepEqual(
          (await store.listByUser(userId)).map((s) => s.id),
          [b.id],
        );

        assert.equal(await store.get(a.id), null);
      },
    },
    {
      name: 'epochs start at 0 and every concurrent bump gets a distinct value',
      async run() {
        const userId = uniqueId('user');

        assert.equal(await store.getEpoch(userId), 0);
        const values = await times(50, () => store.bumpEpoch(userId));

        assert.equal(new Set(values).size, 50);
        assert.equal(Math.max(...values), 50);
        assert.equal(await store.getEpoch(userId), 50);
      },
    },
  ];
}

/** The cases that need `delete` to say what it removed: each eviction reported once. */
function deleteReportCases(
  store: SessionStore,
  other: SessionStore,
  context: SessionStoreConformanceOptions,
): ConformanceCase[] {
  const cases: ConformanceCase[] = [
    {
      name: 'delete reports the ids it removed',
      async run() {
        const userId = uniqueId('user');
        const a = sampleSession({ userId });
        const b = sampleSession({ userId });

        await Promise.all([store.create(a, 60_000), store.create(b, 60_000)]);
        const removed = reported(await store.delete(userId, [a.id, uniqueId('missing'), a.id]));

        assert.deepEqual([...removed], [a.id]);
        assert.deepEqual([...reported(await store.delete(userId, [a.id]))], []);
      },
    },
    {
      name: 'of deletes racing on one session, exactly one reports it',
      async run() {
        for (let i = 0; i < 25; i++) {
          const session = sampleSession();

          await store.create(session, 60_000);

          const results = await Promise.all([
            store.delete(session.userId, [session.id]),
            other.delete(session.userId, [session.id]),
          ]);

          const reporters = results.filter((removed) => reported(removed).includes(session.id));

          assert.equal(reporters.length, 1, `iteration ${i}`);
        }
      },
    },
    {
      name: 'logins racing at the per-user cap report each eviction once',
      async run() {
        reported(await store.delete(uniqueId('user'), []));

        for (let i = 0; i < 10; i++) {
          const options = { maxPerUser: 2 };

          const managers = [store, other, store, other].map(
            (s) => new SessionManager(s, options, systemClock, cryptoRandom, silentLogger),
          );

          const userId = uniqueId('user');

          const mint = (manager: SessionManager<unknown>) =>
            manager.mint({
              userId,
              attributes: {},
              rememberMe: false,
              persistentCookie: false,
              authenticatedAt: systemClock.now(),
              meta: { ip: '203.0.113.7' },
            });

          const created: string[] = [];

          for (const manager of managers.slice(0, 2)) {
            const minted = await mint(manager);

            if (minted.ok) created.push(minted.session.id);
          }

          const raced = await Promise.all(managers.map(mint));
          const reported: string[] = [];

          for (const minted of raced) {
            assert.ok(minted.ok, `iteration ${i}: mint refused`);
            created.push(minted.session.id);
            reported.push(...minted.evicted);
          }

          const live = new Set((await store.listByUser(userId)).map((s) => s.id));
          const gone = created.filter((id) => !live.has(id)).sort();

          assert.ok(live.size <= 2, `iteration ${i}: ${live.size} sessions over a cap of 2`);
          assert.deepEqual([...reported].sort(), gone, `iteration ${i}: evictions misreported`);
        }
      },
    },
    {
      name: 'two logins racing at a cap of one leave exactly one session and report once',
      async run() {
        for (let i = 0; i < 10; i++) {
          // One clock for both instances, as in one process: it ticks on
          // every read, so racing mints never tie.
          const start = systemClock.now();
          let tick = start;
          const shared = { now: () => tick++ };
          const options = { maxPerUser: 1 };

          const primary = new SessionManager(store, options, shared, cryptoRandom, silentLogger);
          const secondary = new SessionManager(other, options, shared, cryptoRandom, silentLogger);

          const userId = uniqueId('user');

          const mint = (manager: SessionManager<unknown>, rememberMe: boolean) =>
            manager.mint({
              userId,
              attributes: {},
              rememberMe,
              persistentCookie: false,
              authenticatedAt: start,
              meta: { ip: '203.0.113.7' },
            });

          const existing = await mint(primary, true);

          assert.ok(existing.ok, `iteration ${i}: mint refused`);

          const raced = await Promise.all([
            mint(primary, i % 2 === 0),
            mint(secondary, i % 2 !== 0),
          ]);

          const created = [existing.session.id];
          const reported: string[] = [];

          for (const minted of raced) {
            assert.ok(minted.ok, `iteration ${i}: mint refused`);

            assert.ok(
              !minted.evicted.includes(minted.session.id),
              `iteration ${i}: a mint evicted its own session`,
            );

            created.push(minted.session.id);
            reported.push(...minted.evicted);
          }

          const live = new Set((await store.listByUser(userId)).map((s) => s.id));
          const gone = created.filter((id) => !live.has(id)).sort();

          assert.equal(live.size, 1, `iteration ${i}: ${live.size} sessions at a cap of 1`);
          assert.ok(!live.has(existing.session.id), `iteration ${i}: the older session survived`);
          assert.deepEqual([...reported].sort(), gone, `iteration ${i}: evictions misreported`);
        }
      },
    },
  ];

  if (context.deleteReportsRemoved !== false) return cases;

  return cases.map((testCase) => ({
    name: testCase.name + SKIPPED_DELETE_CASES,
    run: async () => {},
  }));
}
