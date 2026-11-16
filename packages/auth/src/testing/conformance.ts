/**
 * The guarantees every store adapter must give, as runnable cases. These are
 * the properties the flows' security depends on: single-use consumption under
 * concurrency, no session resurrection, every counter key expiring, unique
 * violations returned as null, guarded writes refusing deleted users.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';

import type { NormalizedEmail } from '../email';
import type { CounterStore, SessionStore, StoredSession, StoredToken, TokenStore, UserStore } from '../stores';
import { sleep, times, uniqueId, type ConformanceCase, type ConformanceContext } from './harness';

function advance(context: ConformanceContext): (ms: number) => Promise<void> {
  return context.advanceTime ?? sleep;
}

function sampleSession(overrides: Partial<StoredSession> = {}): StoredSession {
  const now = Date.now();
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

export function sessionStoreConformance(store: SessionStore, context: ConformanceContext = {}): ConformanceCase[] {
  const wait = advance(context);
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
        for (let i = 0; i < 25; i++) {
          const session = sampleSession();
          await store.create(session, 60_000);
          await Promise.all([store.delete(session.userId, [session.id]), store.touch({ ...session, lastActiveAt: session.lastActiveAt + 1 })]);
          assert.equal(await store.get(session.id), null, `iteration ${i}`);
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
        await Promise.all([store.create(a, 60_000), store.create(b, 60_000), store.create(other, 60_000)]);
        const ids = (await store.listByUser(userId)).map((s) => s.id).sort();
        assert.deepEqual(ids, [a.id, b.id].sort());
        await store.delete(userId, [a.id]);
        assert.deepEqual((await store.listByUser(userId)).map((s) => s.id), [b.id]);
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

function sampleToken(overrides: Partial<StoredToken> = {}): StoredToken {
  return {
    purpose: 'conformance',
    userId: uniqueId('user'),
    hash: uniqueId('hash'),
    expiresAt: Date.now() + 60_000,
    attempts: 0,
    data: { email: 'person@example.com' },
    ...overrides,
  };
}

export function tokenStoreConformance(store: TokenStore): ConformanceCase[] {
  return [
    {
      name: 'stores a token and finds it by hash and by user',
      async run() {
        const token = sampleToken();
        await store.put(token);
        assert.deepEqual(await store.find(token.purpose, token.hash), token);
        assert.deepEqual(await store.findByUser(token.purpose, token.userId), token);
        assert.equal(await store.find('other-purpose', token.hash), null);
      },
    },
    {
      name: 'keeps one live token per user and purpose',
      async run() {
        const first = sampleToken();
        const second = sampleToken({ userId: first.userId });
        const otherPurpose = sampleToken({ userId: first.userId, purpose: 'conformance-other' });
        await store.put(first);
        await store.put(otherPurpose);
        await store.put(second);
        assert.equal(await store.find(first.purpose, first.hash), null);
        assert.deepEqual(await store.find(second.purpose, second.hash), second);
        assert.deepEqual(await store.find(otherPurpose.purpose, otherPurpose.hash), otherPurpose);
      },
    },
    {
      name: 'concurrent puts for the same user and purpose never throw and leave one token',
      async run() {
        const userId = uniqueId('user');
        const tokens = Array.from({ length: 20 }, () => sampleToken({ userId }));
        await Promise.all(tokens.map((t) => store.put(t)));
        const live = await Promise.all(tokens.map((t) => store.find(t.purpose, t.hash)));
        assert.equal(live.filter(Boolean).length, 1);
      },
    },
    {
      name: 'consume is single-use under 50 concurrent callers',
      async run() {
        const token = sampleToken();
        await store.put(token);
        const results = await times(50, () => store.consume(token.purpose, token.hash));
        assert.equal(results.filter(Boolean).length, 1);
        assert.equal(await store.find(token.purpose, token.hash), null);
      },
    },
    {
      name: 'incrementAttempts never passes the cap under 50 concurrent callers',
      async run() {
        const token = sampleToken();
        await store.put(token);
        const results = await times(50, () => store.incrementAttempts(token.purpose, token.userId, 5));
        const granted = results.filter((r): r is number => r !== null).sort((a, b) => a - b);
        assert.deepEqual(granted, [1, 2, 3, 4, 5]);
        assert.equal((await store.find(token.purpose, token.hash))?.attempts, 5);
        assert.equal(await store.incrementAttempts(token.purpose, uniqueId('nobody'), 5), null);
      },
    },
    {
      name: 'deletes a user tokens by purpose or entirely',
      async run() {
        const userId = uniqueId('user');
        const a = sampleToken({ userId, purpose: 'conformance-a' });
        const b = sampleToken({ userId, purpose: 'conformance-b' });
        const c = sampleToken({ userId, purpose: 'conformance-c' });
        await Promise.all([store.put(a), store.put(b), store.put(c)]);
        await store.deleteByUser(userId, ['conformance-a']);
        assert.equal(await store.find(a.purpose, a.hash), null);
        assert.notEqual(await store.find(b.purpose, b.hash), null);
        await store.deleteByUser(userId);
        assert.equal(await store.find(b.purpose, b.hash), null);
        assert.equal(await store.find(c.purpose, c.hash), null);
      },
    },
  ];
}

export function counterStoreConformance(store: CounterStore, context: ConformanceContext = {}): ConformanceCase[] {
  const wait = advance(context);
  return [
    {
      name: 'counts hits and never extends the window',
      async run() {
        const key = uniqueId('counter');
        const first = await store.increment(key, 60_000);
        await wait(200);
        const second = await store.increment(key, 60_000);
        const third = await store.increment(key, 60_000);
        assert.deepEqual([first.count, second.count, third.count], [1, 2, 3]);
        assert.ok(Math.abs(third.resetAt - first.resetAt) < 150, 'the window end must not move');
        assert.equal((await store.get(key))?.count, 3);
      },
    },
    {
      name: 'every key expires with its window',
      async run() {
        const key = uniqueId('counter');
        await store.increment(key, 1000);
        await store.increment(key, 1000);
        await wait(1500);
        assert.equal(await store.get(key), null);
        assert.equal((await store.increment(key, 1000)).count, 1);
      },
    },
    {
      name: 'concurrent increments each see a distinct count',
      async run() {
        const key = uniqueId('counter');
        const counts = (await times(50, () => store.increment(key, 60_000))).map((w) => w.count).sort((a, b) => a - b);
        assert.deepEqual(counts, Array.from({ length: 50 }, (_, i) => i + 1));
      },
    },
    {
      name: 'reset removes the counter',
      async run() {
        const key = uniqueId('counter');
        await store.increment(key, 60_000);
        await store.reset(key);
        assert.equal(await store.get(key), null);
        assert.equal(await store.get(uniqueId('never')), null);
      },
    },
  ];
}

export interface UserStoreConformanceOptions {
  /** Soft-deletes a user, if the adapter supports soft deletion. */
  readonly softDelete?: (id: string) => Promise<void>;
}

export function userStoreConformance(store: UserStore, options: UserStoreConformanceOptions = {}): ConformanceCase[] {
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
      },
    });
  }
  return cases;
}
