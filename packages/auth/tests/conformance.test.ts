import { describe, it } from 'vitest';

import {
  counterStoreConformance,
  manualClock,
  memoryStores,
  runConformance,
  sessionStoreConformance,
  tokenStoreConformance,
  userStoreConformance,
} from '../src/testing';

// The in-memory stores must meet the same bar as a real adapter. Time moves on
// a manual clock, so the TTL cases run instantly. The clock starts at the real
// time because the sample records carry Date.now() timestamps.
const clock = manualClock(Date.now());
const stores = memoryStores(clock);
const context = { advanceTime: async (ms: number) => clock.advance(ms) };
const api = { describe, it };

runConformance('memory session store', sessionStoreConformance(stores.sessions, context), api);
runConformance('memory token store', tokenStoreConformance(stores.tokens), api);
runConformance('memory counter store', counterStoreConformance(stores.counters, context), api);
runConformance(
  'memory user store',
  userStoreConformance(stores.users, { softDelete: (id) => stores.users.softDelete(id) }),
  api,
);
