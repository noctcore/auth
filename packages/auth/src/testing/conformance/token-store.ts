/**
 * TokenStore conformance: single-use consumption under concurrency and an
 * attempt cap that cannot be overrun.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';
import { systemClock } from '../../ports/clock';
import type { StoredToken, TokenStore } from '../../ports/stores';
import { times, uniqueId, type ConformanceCase } from '../harness';

function sampleToken(overrides: Partial<StoredToken> = {}): StoredToken {
  return {
    purpose: 'conformance',
    userId: uniqueId('user'),
    hash: uniqueId('hash'),
    expiresAt: systemClock.now() + 60_000,
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

        const results = await times(50, () =>
          store.incrementAttempts(token.purpose, token.userId, 5),
        );

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
