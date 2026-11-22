import { describe, expect, it } from 'vitest';

import {
  counterStoreConformance,
  manualClock,
  invitationStoreConformance,
  memoryStores,
  MemoryInvitationStore,
  membershipStoreConformance,
  MemoryMembershipStore,
  MemorySessionStore,
  runConformance,
  sessionStoreConformance,
  tokenStoreConformance,
  twoFactorStoreConformance,
  MemoryTwoFactorStore,
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

runConformance(
  'memory two-factor store',
  twoFactorStoreConformance(new MemoryTwoFactorStore()),
  api,
);

runConformance(
  'memory membership store',
  membershipStoreConformance(new MemoryMembershipStore()),
  api,
);

runConformance(
  'memory invitation store',
  invitationStoreConformance(new MemoryInvitationStore(), context),
  api,
);

describe('session store conformance for a delete that reports nothing', () => {
  // A store on the older contract: delete removes but answers nothing.
  const silent = new MemorySessionStore(clock);
  const remove = silent.delete.bind(silent);

  silent.delete = async (userId: string, ids: readonly string[]) => {
    await remove(userId, ids);

    return undefined as never;
  };

  const deleteCase = (name: string) => name.startsWith('delete reports the ids it removed');

  it('fails the delete cases with a message naming the opt-out', async () => {
    const found = sessionStoreConformance(silent, context).find((c) => deleteCase(c.name));

    await expect(found?.run()).rejects.toThrow(/deleteReportsRemoved: false/u);
  });

  it('lists them as skipped when the store opts out', async () => {
    const cases = sessionStoreConformance(silent, { ...context, deleteReportsRemoved: false });

    const skipped = cases.filter((c) =>
      c.name.endsWith('(skipped: deleteReportsRemoved is false)'),
    );

    expect(skipped).toHaveLength(4);

    for (const c of skipped) await c.run();
  });
});
