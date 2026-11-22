// A038 (and A001) on a real Redis: a parallel burst over many connections
// gets no more attempts than the budget.
//
// The in-memory store runs every call to completion before the next, so it
// cannot show a gap between reading the lock and counting the attempt. Redis
// with many connections and jittered requests can: a request that read "no
// lock" just before another one locked used to count against a counter the
// lock had just reset, and got through.
//
// Stopped by: throttle/throttle.ts (a lock never resets the attempt counter;
// it keeps it above the limit for as long as the lock lasts).
import { Redis } from 'ioredis';
import { afterAll, describe, expect, it } from 'vitest';
import { Throttle, systemClock } from '@noctcore/auth';
import { uniqueId } from '@noctcore/auth/testing';
import { RedisCounterStore } from '../src';

const url = process.env['REDIS_URL'];
const required = process.env['AUTH_REQUIRE_SERVICES'] === '1';

if (!url && required) throw new Error('REDIS_URL is required when AUTH_REQUIRE_SERVICES=1');

const CONNECTIONS = 16;
const ATTEMPTS = 120;

describe.skipIf(!url)('parallel bursts against the redis counter store', () => {
  const prefix = `${uniqueId('burst')}:`;

  const clients = Array.from(
    { length: CONNECTIONS },
    () =>
      new Redis(url ?? 'redis://localhost:6390', { lazyConnect: false, maxRetriesPerRequest: 1 }),
  );

  // One throttle per connection, as separate server processes would have.
  const throttles = clients.map(
    (redis) => new Throttle(new RedisCounterStore(redis, { prefix }), systemClock),
  );

  const counters = new RedisCounterStore(clients[0] as Redis, { prefix });

  afterAll(async () => {
    const [first] = clients;
    const keys = (await first?.keys(`${prefix}*`)) ?? [];

    if (keys.length > 0) await first?.del(...keys);

    await Promise.all(clients.map((redis) => redis.quit()));
  });

  /** Runs `attempt` ATTEMPTS times over every connection, each after a small random delay. */
  async function burst(attempt: (throttle: Throttle) => Promise<boolean>): Promise<number> {
    const results = await Promise.all(
      Array.from({ length: ATTEMPTS }, async (_, i) => {
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 20));

        return attempt(throttles[i % CONNECTIONS] as Throttle);
      }),
    );

    return results.filter(Boolean).length;
  }

  it('A038: lets at most the factor budget through, from every connection together', async () => {
    for (let round = 0; round < 5; round++) {
      const account = uniqueId('factor');
      const rule = { limit: 5, window: '15m' } as const;
      const allowed = await burst(async (t) => (await t.gateFactor(account, rule)).allowed);

      expect(allowed).toBeLessThanOrEqual(5);
    }
  });

  it('A001: lets at most the account-wide password budget through, from many IPs', async () => {
    for (let round = 0; round < 5; round++) {
      const account = uniqueId('login');
      let ip = 0;

      const allowed = await burst(
        async (t) => (await t.gateLogin(account, `198.51.100.${ip++ % 250}`)).allowed,
      );

      // perAccount defaults to 10 per 15 minutes.
      expect(allowed).toBeLessThanOrEqual(10);

      // However many requests crossed the limit, the burst made one lock and one tier step.
      expect((await counters.get(`tier:${account}`))?.count).toBe(1);
    }
  });

  it('A102: lets at most the trusted-device budget through a lock, over login devices and session doors together', async () => {
    for (let round = 0; round < 5; round++) {
      const account = uniqueId('locked');

      // Lock the account: the eleventh attempt crosses the account-wide budget.
      for (let i = 0; i < 11; i++)
        await (throttles[0] as Throttle).gateLogin(account, `192.0.2.${i}`);

      let n = 0;

      // Half the burst carries login device ids, half the ids live sessions stand in for.
      const allowed = await burst(async (t) => {
        const i = n++;
        const deviceId = i % 2 === 0 ? `device-${i % 7}` : `session-device-${i % 5}`;

        return (await t.gateLogin(account, `198.51.100.${i % 250}`, deviceId)).allowed;
      });

      // perDevice defaults to 5 per 15 minutes, shared by every device of the account.
      expect(allowed).toBeLessThanOrEqual(5);
    }
  });
});
