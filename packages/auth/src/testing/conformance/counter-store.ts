/**
 * CounterStore conformance: atomic increments and every counter key expiring.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';
import type { CounterStore } from '../../ports/stores';
import { systemClock } from '../../ports/clock';
import {
  advance,
  times,
  uniqueId,
  type ConformanceCase,
  type ConformanceContext,
} from '../harness';

export function counterStoreConformance(
  store: CounterStore,
  context: ConformanceContext = {},
): ConformanceCase[] {
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

        const counts = (await times(50, () => store.increment(key, 60_000)))
          .map((w) => w.count)
          .sort((a, b) => a - b);

        assert.deepEqual(
          counts,
          Array.from({ length: 50 }, (_, i) => i + 1),
        );
      },
    },
    {
      name: 'decrement takes one back, keeps the TTL, never goes below 0 and never creates a key',
      async run() {
        const key = uniqueId('counter');
        const first = await store.increment(key, 60_000);

        await store.increment(key, 60_000);
        await store.increment(key, 60_000);
        await store.decrement(key);
        const after = await store.get(key);

        assert.equal(after?.count, 2);

        assert.ok(
          Math.abs((after?.resetAt ?? 0) - first.resetAt) < 150,
          'decrement must not move the window end',
        );

        await times(10, () => store.decrement(key));
        assert.equal((await store.get(key))?.count, 0, 'never below 0');
        assert.equal((await store.increment(key, 60_000)).count, 1);
        const missing = uniqueId('never');

        await store.decrement(missing);
        assert.equal(await store.get(missing), null);
      },
    },
    {
      name: 'concurrent increments and decrements net out exactly',
      async run() {
        const key = uniqueId('counter');

        await times(20, () => store.increment(key, 60_000));

        await Promise.all([
          times(10, () => store.decrement(key)),
          times(10, () => store.increment(key, 60_000)),
        ]);

        assert.equal((await store.get(key))?.count, 20);
      },
    },
    {
      name: 'set overwrites the count and arms a fresh TTL',
      async run() {
        const key = uniqueId('counter');

        await store.increment(key, 1000);
        await store.set(key, 7, 60_000);
        const window = await store.get(key);

        assert.equal(window?.count, 7);

        assert.ok(
          (window?.resetAt ?? 0) - systemClock.now() > 30_000,
          'set must replace the old TTL',
        );

        assert.equal((await store.increment(key, 1000)).count, 8);
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
