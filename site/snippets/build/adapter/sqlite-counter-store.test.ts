import { DatabaseSync } from 'node:sqlite';
import { describe, it } from 'node:test';
import { counterStoreConformance, manualClock, runConformance } from '@noctcore/auth/testing';
import { SqliteCounterStore } from './sqlite-counter-store.ts';

// A manual clock makes the expiry cases instant instead of sleeping. It starts
// at the real time because some cases compare against Date.now().
const clock = manualClock(Date.now());
const store = new SqliteCounterStore(new DatabaseSync(':memory:'), clock);

runConformance(
  'sqlite counter store',
  counterStoreConformance(store, { advanceTime: async (ms) => clock.advance(ms) }),
  {
    describe,
    // node:test takes its options before the test body; Vitest and Jest can
    // pass their own `it` unchanged.
    it: (name, body, timeout) => it(name, { timeout }, body),
  },
);
