/**
 * TokenStore conformance: single-use consumption under concurrency, an
 * attempt cap that cannot be overrun, and an extend that never revives a
 * consumed token.
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

function requireExtendExpiry(store: TokenStore): NonNullable<TokenStore['extendExpiry']> {
  return (purpose, hash, expiresAt) => {
    assert.ok(
      typeof store.extendExpiry === 'function',
      'TokenStore.extendExpiry is missing: without it a one-time link is extended by a consume and a put',
    );

    return store.extendExpiry(purpose, hash, expiresAt);
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
      name: 'consume by the hash of a replaced token leaves the token that replaced it',
      async run() {
        // A refused code is removed by the hash that was read, so a code
        // issued meanwhile (a resend) must survive that delete.
        const read = sampleToken();
        const resent = sampleToken({ userId: read.userId });

        await store.put(read);
        await store.put(resent);
        assert.equal(await store.consume(read.purpose, read.hash), null);
        assert.deepEqual(await store.findByUser(read.purpose, read.userId), resent);
      },
    },
    {
      name: 'extendExpiry moves the expiry of a live token, keeps the rest, and creates nothing',
      async run() {
        const extendExpiry = requireExtendExpiry(store);
        const token = sampleToken({ attempts: 2 });
        const later = token.expiresAt + 60_000;

        await store.put(token);
        assert.equal(await extendExpiry(token.purpose, token.hash, later), true);

        assert.deepEqual(await store.find(token.purpose, token.hash), {
          ...token,
          expiresAt: later,
        });

        assert.equal(await extendExpiry('other-purpose', token.hash, later), false);
        assert.equal(await extendExpiry(token.purpose, uniqueId('hash'), later), false);
        assert.equal(await store.find('other-purpose', token.hash), null);
      },
    },
    {
      name: 'extendExpiry never brings back a consumed token, also when racing the consume',
      async run() {
        const extendExpiry = requireExtendExpiry(store);
        const spent = sampleToken();

        await store.put(spent);
        await store.consume(spent.purpose, spent.hash);
        assert.equal(await extendExpiry(spent.purpose, spent.hash, Date.UTC(9999, 11, 31)), false);
        assert.equal(await store.find(spent.purpose, spent.hash), null);

        // Whichever lands first, the consume wins and the token is gone.
        for (let round = 0; round < 20; round++) {
          const token = sampleToken();

          await store.put(token);

          const [consumed] = await Promise.all([
            store.consume(token.purpose, token.hash),
            extendExpiry(token.purpose, token.hash, Date.UTC(9999, 11, 31)),
          ]);

          assert.notEqual(consumed, null);
          assert.equal(await store.find(token.purpose, token.hash), null);
          assert.equal(await store.findByUser(token.purpose, token.userId), null);
        }
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
    {
      name: 'keeps the email change purposes apart: a revert link lives for days beside a pending change, a block, an address hold and a lockout',
      async run() {
        // The email change flows keep three tokens per user at once: the
        // pending change, the revert link (7 days or more) and a block, and
        // void the change and reset purposes without touching the revert link.
        const userId = uniqueId('user');
        const week = 7 * 24 * 60 * 60 * 1000;
        const change = sampleToken({ userId, purpose: 'email-change' });

        const revert = sampleToken({
          userId,
          purpose: 'email-revert',
          expiresAt: systemClock.now() + week + 60_000,
          data: { email: 'old@example.com', to: 'new@example.com' },
        });

        const block = sampleToken({ userId, purpose: 'email-change-block' });

        await Promise.all([store.put(change), store.put(revert), store.put(block)]);
        assert.deepEqual(await store.findByUser('email-revert', userId), revert);
        await store.deleteByUser(userId, ['email-change', 'password-reset']);
        assert.equal(await store.find(change.purpose, change.hash), null);
        assert.deepEqual(await store.find(revert.purpose, revert.hash), revert);
        assert.deepEqual(await store.findByUser('email-change-block', userId), block);
        assert.deepEqual(await store.consume(revert.purpose, revert.hash), revert);
        assert.equal(await store.consume(revert.purpose, revert.hash), null);

        // A hold on an address is filed under its owner and found by its hash
        // alone; a revert lockout sits beside it. A lockout, and the revert
        // link it keeps, never lapse: both are stored to expire at the start
        // of 9999-12-31 UTC, which the store must keep exactly.
        const never = Date.UTC(9999, 11, 31);
        const hold = sampleToken({ userId, purpose: 'email-reserved' });
        const lockout = sampleToken({ userId, purpose: 'email-revert-lockout', expiresAt: never });

        await Promise.all([store.put(hold), store.put(lockout)]);
        assert.deepEqual(await store.find('email-reserved', hold.hash), hold);
        await store.deleteByUser(userId, ['email-reserved']);
        assert.equal(await store.find('email-reserved', hold.hash), null);
        assert.deepEqual(await store.findByUser('email-revert-lockout', userId), lockout);
      },
    },
  ];
}
