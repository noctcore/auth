import { beforeEach, describe, expect, it } from 'vitest';

import { manualClock, MemoryCounterStore, type ManualClock } from '../../src/testing';
import { accountKey, Throttle } from '../../src/throttle';

const MIN = 60_000;
let clock: ManualClock;
let counters: MemoryCounterStore;
let throttle: Throttle;
const victim = accountKey('victim@example.com');

beforeEach(() => {
  clock = manualClock();
  counters = new MemoryCounterStore(clock);
  throttle = new Throttle(counters, clock);
});

describe('fixed-window rate limit', () => {
  it('allows the limit, refuses after it, and marks only the first refusal', async () => {
    const rule = { limit: 2, window: '1m' } as const;
    const hits = [];
    for (let i = 0; i < 4; i++) hits.push(await throttle.hit('login:1.2.3.4', rule));
    expect(hits.map((h) => h.allowed)).toEqual([true, true, false, false]);
    expect(hits.map((h) => h.firstRefusal)).toEqual([false, false, true, false]);
    expect(hits[2]?.retryAfterSeconds).toBe(60);
    clock.advance(MIN);
    expect((await throttle.hit('login:1.2.3.4', rule)).allowed).toBe(true);
  });

  it('fails closed when the store throws', async () => {
    counters.increment = async () => {
      throw new Error('redis down');
    };
    await expect(throttle.hit('x', { limit: 1, window: '1m' })).rejects.toThrow('redis down');
  });
});

describe('login lockout', () => {
  it('stops one source after 5 attempts without locking the owner on another network', async () => {
    for (let i = 0; i < 5; i++) expect((await throttle.gateLogin(victim, '6.6.6.6')).allowed).toBe(true);
    expect(await throttle.gateLogin(victim, '6.6.6.6')).toEqual({ allowed: false, reason: 'account_ip_budget' });
    expect((await throttle.gateLogin(victim, '198.51.100.1')).allowed).toBe(true);
  });

  it('locks the account after the account-wide budget with a capped, growing lock', async () => {
    const lockFor = async () => {
      let gate;
      for (let ip = 1; ; ip++) {
        gate = await throttle.gateLogin(victim, `10.0.0.${ip}`);
        if (!gate.allowed) break;
      }
      return gate;
    };
    const first = await lockFor();
    expect(first).toEqual({ allowed: false, reason: 'locked', newLock: { until: clock.now() + 5 * MIN } });
    expect(await throttle.gateLogin(victim, '198.51.100.1')).toEqual({ allowed: false, reason: 'locked' });

    clock.advance(5 * MIN);
    const second = await lockFor();
    expect(second).toEqual({ allowed: false, reason: 'locked', newLock: { until: clock.now() + 15 * MIN } });
    clock.advance(15 * MIN);
    const third = await lockFor();
    expect(third).toEqual({ allowed: false, reason: 'locked', newLock: { until: clock.now() + 45 * MIN } });
    clock.advance(45 * MIN);
    const fourth = await lockFor();
    expect(fourth).toEqual({ allowed: false, reason: 'locked', newLock: { until: clock.now() + 60 * MIN } });
    clock.advance(60 * MIN);
    expect((await throttle.gateLogin(victim, '198.51.100.1')).allowed).toBe(true);
  });

  it('decays the backoff tier after the quiet period', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });
    await t.gateLogin(victim, 'a');
    expect((await t.gateLogin(victim, 'b')).allowed).toBe(false);
    clock.advance(24 * 60 * MIN);
    await t.gateLogin(victim, 'c');
    expect(await t.gateLogin(victim, 'd')).toEqual({ allowed: false, reason: 'locked', newLock: { until: clock.now() + 5 * MIN } });
  });

  it('returns the budgets on success and lifts everything on a password reset', async () => {
    for (let i = 0; i < 4; i++) await throttle.gateLogin(victim, '1.1.1.1');
    await throttle.loginSucceeded(victim, '1.1.1.1');
    for (let i = 0; i < 5; i++) expect((await throttle.gateLogin(victim, '1.1.1.1')).allowed).toBe(true);

    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });
    const other = accountKey('other@example.com');
    await t.gateLogin(other, 'a');
    await t.gateLogin(other, 'b');
    await t.clearAccount(other);
    expect((await t.gateLogin(other, 'c')).allowed).toBe(true);
  });

  it('derives keys from the email so unknown addresses do the same work', () => {
    expect(accountKey('a@example.com')).toMatch(/^[0-9a-f]{64}$/u);
    expect(accountKey('a@example.com')).not.toBe(accountKey('b@example.com'));
  });
});
