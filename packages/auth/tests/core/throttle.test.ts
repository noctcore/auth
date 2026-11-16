import { beforeEach, describe, expect, it } from 'vitest';

import { manualClock, MemoryCounterStore, type ManualClock } from '../../src/testing';
import { createDeviceToken, verifyDeviceToken } from '../../src/device';
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

  it('returns only the proving source budget on success and lifts everything on a password reset', async () => {
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

  it('keeps the account-wide budget spent after one source succeeds', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 3, window: '15m' } });
    await t.gateLogin(victim, 'attacker-1');
    await t.gateLogin(victim, 'attacker-2');
    await t.gateLogin(victim, 'owner');
    await t.loginSucceeded(victim, 'owner');
    // The attackers' attempts still count: the next one locks.
    expect((await t.gateLogin(victim, 'attacker-3')).allowed).toBe(false);
  });

  it('renews the quiet period on every lock, so the tier only decays after a full quiet day', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });
    const lockOnce = async (ip: string) => {
      await t.gateLogin(victim, `${ip}-a`);
      return t.gateLogin(victim, `${ip}-b`);
    };
    await lockOnce('1');
    clock.advance(20 * 60 * MIN);
    expect(await lockOnce('2')).toMatchObject({ newLock: { until: clock.now() + 15 * MIN } });
    clock.advance(20 * 60 * MIN);
    // 40 h after the first lock but only 20 h after the last: still escalating.
    expect(await lockOnce('3')).toMatchObject({ newLock: { until: clock.now() + 45 * MIN } });
    clock.advance(24 * 60 * MIN);
    expect(await lockOnce('4')).toMatchObject({ newLock: { until: clock.now() + 5 * MIN } });
  });
});

describe('trusted devices', () => {
  const key = new TextEncoder().encode('device-key-device-key-device-key');
  const DAY = 24 * 60 * MIN;
  const claims = { userId: 'user-1', epoch: 2, issuedAt: Date.UTC(2026, 0, 1) };
  const check = (over: Partial<{ userId: string; epoch: number; now: number; maxAgeMs: number }> = {}) => ({
    userId: 'user-1',
    epoch: 2,
    now: claims.issuedAt + DAY,
    maxAgeMs: 30 * DAY,
    ...over,
  });

  it('binds a device id to the user, the epoch and the issue time', () => {
    const token = createDeviceToken(key, claims);
    expect(verifyDeviceToken(key, token, check())).toMatch(/^[0-9a-f]{32}$/u);
    expect(verifyDeviceToken(key, token, check({ userId: 'user-2' }))).toBeNull();
    // A password change, a reset or revoke-all bumps the epoch: the token is void.
    expect(verifyDeviceToken(key, token, check({ epoch: 3 }))).toBeNull();
    // Older than the max age, whatever the cookie says.
    expect(verifyDeviceToken(key, token, check({ now: claims.issuedAt + 31 * DAY }))).toBeNull();
    expect(verifyDeviceToken(key, token, check({ now: claims.issuedAt - 5 * MIN }))).toBeNull();
    const [id, issued, epoch] = token.split('.');
    expect(verifyDeviceToken(key, `${id}.${issued}.${epoch}.${'0'.repeat(64)}`, check())).toBeNull();
    // Moving the issue time forward breaks the HMAC.
    expect(verifyDeviceToken(key, token.replace(`.${issued}.`, `.${claims.issuedAt + DAY}.`), check())).toBeNull();
    expect(verifyDeviceToken(key, 'nope', check())).toBeNull();
    // One spelling per token: a leading zero in the issue time or the epoch is refused.
    expect(verifyDeviceToken(key, token.replace(`.${issued}.`, `.0${issued}.`), check())).toBeNull();
    expect(verifyDeviceToken(key, token.replace(`.${issued}.${epoch}.`, `.${issued}.0${epoch}.`), check())).toBeNull();
  });

  it('ignores device tokens while the account is unlocked, so correct logins never spend a device budget', async () => {
    for (let i = 0; i < 10; i++) {
      expect(await throttle.gateLogin(victim, 'owner', 'device-1')).toEqual({ allowed: true });
      await throttle.loginSucceeded(victim, 'owner', null);
    }
  });

  it('under a lock, lets correct device logins through and stops after five device failures in all', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });
    await t.gateLogin(victim, 'a');
    expect((await t.gateLogin(victim, 'b')).allowed).toBe(false);
    // Correct logins hand their reserved attempt back: ten in a row all pass.
    for (let i = 0; i < 10; i++) {
      expect(await t.gateLogin(victim, 'owner', 'device-0')).toEqual({ allowed: true, viaDevice: true });
      await t.loginSucceeded(victim, 'owner', 'device-0');
    }
    // Five failures spread over five devices spend the shared budget: a sixth device gets nothing.
    for (let i = 1; i <= 5; i++) {
      expect((await t.gateLogin(victim, 'x', `device-${i}`)).allowed).toBe(true);
      await t.deviceFailed(victim);
    }
    expect(await t.gateLogin(victim, 'x', 'device-9')).toEqual({ allowed: false, reason: 'device_budget' });
  });

  it('caps one device at its own budget even before any failure is recorded (parallel burst)', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });
    await t.gateLogin(victim, 'a');
    await t.gateLogin(victim, 'b');
    const gates = await Promise.all(Array.from({ length: 20 }, () => t.gateLogin(victim, 'x', 'device-1')));
    expect(gates.filter((g) => g.allowed)).toHaveLength(5);
  });

  it('counts a wrong password made under a lock with a device against the account-wide budget', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 3, window: '15m' } });
    for (let i = 0; i < 4; i++) await t.gateLogin(victim, `ip-${i}`);
    expect((await t.gateLogin(victim, 'stranger')).allowed).toBe(false);
    for (let i = 0; i < 3; i++) {
      await t.gateLogin(victim, 'owner', 'device-1');
      expect(await t.deviceFailed(victim)).toEqual({});
    }
    // The fourth device failure spends the account budget again and renews the lock.
    await t.gateLogin(victim, 'owner', 'device-1');
    expect(await t.deviceFailed(victim)).toHaveProperty('newLock');
  });

  it('probe A: the owner signs in every hour while an attacker spreads failures across IPs', async () => {
    let ip = 0;
    for (let hour = 0; hour < 48; hour++) {
      // Thirty failures an hour from thirty fresh IPs keep the account locked for everyone else.
      for (let i = 0; i < 30; i++) await throttle.gateLogin(victim, `192.0.2.${ip++ % 250}-${hour}`);
      expect((await throttle.gateLogin(victim, `198.51.100.${hour}`)).allowed).toBe(false);
      const owner = await throttle.gateLogin(victim, '203.0.113.5', 'owner-device');
      expect(owner.allowed).toBe(true);
      await throttle.loginSucceeded(victim, '203.0.113.5', 'owner-device');
      clock.advance(60 * MIN);
    }
  });
});
