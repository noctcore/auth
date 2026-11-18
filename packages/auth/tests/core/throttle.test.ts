import { beforeEach, describe, expect, it, vi } from 'vitest';

import { LOCKOUT_EXPIRES_AT } from '../../src/shared/duration';
import { manualClock, MemoryCounterStore, type ManualClock } from '../../src/testing';
import { createDeviceToken, verifyDeviceToken } from '../../src/throttle/device-token';
import { accountKey } from '../../src/throttle/counter-keys';
import { Throttle } from '../../src/throttle/throttle';

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

    for (let i = 0; i < 4; i++) hits.push(await throttle.hit('login:192.0.2.34', rule));

    expect(hits.map((h) => h.allowed)).toEqual([true, true, false, false]);
    expect(hits.map((h) => h.firstRefusal)).toEqual([false, false, true, false]);
    expect(hits[2]?.retryAfterSeconds).toBe(60);
    clock.advance(MIN);
    expect((await throttle.hit('login:192.0.2.34', rule)).allowed).toBe(true);
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
    for (let i = 0; i < 5; i++)
      expect((await throttle.gateLogin(victim, '198.51.100.66')).allowed).toBe(true);

    expect(await throttle.gateLogin(victim, '198.51.100.66')).toEqual({
      allowed: false,
      reason: 'account_ip_budget',
    });

    expect((await throttle.gateLogin(victim, '198.51.100.1')).allowed).toBe(true);
  });

  it('decays the backoff tier after the quiet period', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });

    await t.gateLogin(victim, 'a');
    expect((await t.gateLogin(victim, 'b')).allowed).toBe(false);
    clock.advance(24 * 60 * MIN);
    await t.gateLogin(victim, 'c');

    expect(await t.gateLogin(victim, 'd')).toEqual({
      allowed: false,
      reason: 'locked',
      newLock: { until: clock.now() + 5 * MIN },
    });
  });

  it('returns only the proving source budget on success and lifts everything on a password reset', async () => {
    for (let i = 0; i < 4; i++) await throttle.gateLogin(victim, '198.51.100.11');

    await throttle.loginSucceeded(victim, '198.51.100.11');

    for (let i = 0; i < 5; i++)
      expect((await throttle.gateLogin(victim, '198.51.100.11')).allowed).toBe(true);

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

  const check = (
    over: Partial<{ userId: string; epoch: number; now: number; maxAgeMs: number }> = {},
  ) => ({
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

    expect(
      verifyDeviceToken(key, `${id}.${issued}.${epoch}.${'0'.repeat(64)}`, check()),
    ).toBeNull();

    // Moving the issue time forward breaks the HMAC.
    expect(
      verifyDeviceToken(key, token.replace(`.${issued}.`, `.${claims.issuedAt + DAY}.`), check()),
    ).toBeNull();

    expect(verifyDeviceToken(key, 'nope', check())).toBeNull();

    // One spelling per token: a leading zero in the issue time or the epoch is refused.
    expect(
      verifyDeviceToken(key, token.replace(`.${issued}.`, `.0${issued}.`), check()),
    ).toBeNull();

    expect(
      verifyDeviceToken(
        key,
        token.replace(`.${issued}.${epoch}.`, `.${issued}.0${epoch}.`),
        check(),
      ),
    ).toBeNull();
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
      expect(await t.gateLogin(victim, 'owner', 'device-0')).toEqual({
        allowed: true,
        viaDevice: true,
      });

      await t.loginSucceeded(victim, 'owner', 'device-0');
    }

    // Five failures spread over five devices spend the shared budget: a sixth device gets nothing.
    for (let i = 1; i <= 5; i++) {
      expect((await t.gateLogin(victim, 'x', `device-${i}`)).allowed).toBe(true);
      await t.deviceFailed(victim);
    }

    expect(await t.gateLogin(victim, 'x', 'device-9')).toEqual({
      allowed: false,
      reason: 'device_budget',
    });
  });

  it('caps one device at its own budget even before any failure is recorded (parallel burst)', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });

    await t.gateLogin(victim, 'a');
    await t.gateLogin(victim, 'b');

    const gates = await Promise.all(
      Array.from({ length: 20 }, () => t.gateLogin(victim, 'x', 'device-1')),
    );

    expect(gates.filter((g) => g.allowed)).toHaveLength(5);
  });

  it('caps a parallel burst over many devices at the shared budget, and refunds both slots on success', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 1, window: '15m' } });

    await t.gateLogin(victim, 'a');
    await t.gateLogin(victim, 'b');

    // A correct login under the lock hands back its own and its shared slot.
    expect(await t.gateLogin(victim, 'owner', 'device-0')).toEqual({
      allowed: true,
      viaDevice: true,
    });

    await t.loginSucceeded(victim, 'owner', 'device-0');
    expect((await counters.get(`devs:${victim}`))?.count).toBe(0);
    expect((await counters.get(`dev:${victim}:device-0`))?.count).toBe(0);

    // Four devices, twenty attempts each, all at once: five get through in all.
    const burst = Array.from({ length: 80 }, (_, i) =>
      t.gateLogin(victim, 'x', `device-${(i % 4) + 1}`),
    );

    expect((await Promise.all(burst)).filter((g) => g.allowed)).toHaveLength(5);
    // Refused attempts handed their reservations back: only the five admitted ones are held.
    expect((await counters.get(`devs:${victim}`))?.count).toBe(5);
  });

  it('holds one device to its own budget across a reset of the shared window', async () => {
    const t = new Throttle(counters, clock, {
      perAccount: { limit: 1, window: '15m' },
      baseLock: '2h',
      maxLock: '2h',
    });

    await t.gateLogin(victim, 'a');
    await t.gateLogin(victim, 'b');

    // device-1 opens the shared window; device-2 starts its own window 14 minutes later.
    expect((await t.gateLogin(victim, 'x', 'device-1')).allowed).toBe(true);
    clock.advance(14 * MIN);

    for (let i = 0; i < 4; i++)
      expect((await t.gateLogin(victim, 'x', 'device-2')).allowed).toBe(true);

    // The shared window starts over; device-2's own window still has one slot left.
    clock.advance(2 * MIN);
    expect((await t.gateLogin(victim, 'x', 'device-2')).allowed).toBe(true);

    expect(await t.gateLogin(victim, 'x', 'device-2')).toEqual({
      allowed: false,
      reason: 'device_budget',
    });
  });

  it('counts a wrong password made under a lock with a device against the account-wide budget', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 3, window: '15m' } });

    for (let i = 0; i < 4; i++) await t.gateLogin(victim, `ip-${i}`);

    expect((await t.gateLogin(victim, 'stranger')).allowed).toBe(false);

    for (let i = 0; i < 3; i++) {
      await t.gateLogin(victim, 'owner', 'device-1');
      expect(await t.deviceFailed(victim)).toEqual({});
    }

    // The fourth device failure spends the account budget again, but the lock is
    // already running: no second notice, and the tier stays where the lock set it.
    await t.gateLogin(victim, 'owner', 'device-1');
    expect(await t.deviceFailed(victim)).toEqual({});
    expect((await counters.get(`acct:${victim}`))?.count).toBe(8);
    expect((await counters.get(`tier:${victim}`))?.count).toBe(1);

    // So the next lock is one tier up (15 minutes), not two (45).
    clock.advance(5 * MIN);

    for (let i = 0; i < 3; i++) await t.gateLogin(victim, `later-${i}`);

    expect(await t.gateLogin(victim, 'later-3')).toEqual({
      allowed: false,
      reason: 'locked',
      newLock: { until: clock.now() + 15 * MIN },
    });
  });
});

describe('second-factor lockout', () => {
  const factor = 'factor-account';
  const rule = { limit: 3, window: '15m' } as const;

  it('reserves an attempt per call, locks after the budget with capped backoff, and answers locked alike', async () => {
    const gates = [];

    for (let i = 0; i < 5; i++) gates.push(await throttle.gateFactor(factor, rule));

    expect(gates.map((g) => g.allowed)).toEqual([true, true, true, false, false]);
    expect(gates[3]).toEqual({ allowed: false, newLock: { until: clock.now() + 5 * MIN } });
    expect(gates[4]).toEqual({ allowed: false });

    // The lock lifts after 5 minutes; the next spent budget locks for 15 (the tier grew).
    clock.advance(5 * MIN);

    for (let i = 0; i < 3; i++)
      expect((await throttle.gateFactor(factor, rule)).allowed).toBe(true);

    expect(await throttle.gateFactor(factor, rule)).toEqual({
      allowed: false,
      newLock: { until: clock.now() + 15 * MIN },
    });

    clock.advance(15 * MIN);
    expect((await throttle.gateFactor(factor, rule)).allowed).toBe(true);
  });

  it('caps the factor lock like the password lock', async () => {
    const capped = new Throttle(counters, clock, { baseLock: '30m', maxLock: '45m' });

    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 3; i++) await capped.gateFactor(factor, rule);

      const lock = await capped.gateFactor(factor, rule);

      expect(!lock.allowed && lock.newLock?.until).toBe(
        clock.now() + (round === 0 ? 30 : 45) * MIN,
      );

      clock.advance(45 * MIN);
    }
  });

  it('counts per account, apart from the password lockout', async () => {
    for (let i = 0; i < 4; i++) await throttle.gateFactor(factor, rule);

    expect((await throttle.gateFactor(factor, rule)).allowed).toBe(false);
    expect((await throttle.gateFactor('another-account', rule)).allowed).toBe(true);
    expect((await throttle.gateLogin(factor, '192.0.2.1')).allowed).toBe(true);
  });

  it('starts the budget over after a correct code', async () => {
    for (let i = 0; i < 3; i++) await throttle.gateFactor(factor, rule);

    await throttle.factorSucceeded(factor);

    for (let i = 0; i < 3; i++)
      expect((await throttle.gateFactor(factor, rule)).allowed).toBe(true);
  });

  it('holds a parallel burst to the budget', async () => {
    const gates = await Promise.all(
      Array.from({ length: 20 }, () => throttle.gateFactor(factor, rule)),
    );

    expect(gates.filter((g) => g.allowed)).toHaveLength(3);
  });
});

describe('a lock holds the attempt counter', () => {
  const rule = { limit: 3, window: '15m' } as const;

  /** Answers "no lock" to every lock read, as a request that read just before the lock was set. */
  function staleLockReads(): void {
    const get = counters.get.bind(counters);

    counters.get = (key) => (key.startsWith('lock:') ? Promise.resolve(null) : get(key));
  }

  it('keeps the factor counter above the limit for as long as the lock lasts', async () => {
    for (let i = 0; i < 4; i++) await throttle.gateFactor('acct', rule);

    expect((await counters.get('acct:2fa:acct'))?.count).toBe(4);
    clock.advance(5 * MIN - 1);
    expect((await counters.get('acct:2fa:acct'))?.count).toBe(4);
    clock.advance(1);
    expect(await counters.get('acct:2fa:acct')).toBeNull();
    expect((await throttle.gateFactor('acct', rule)).allowed).toBe(true);
  });

  it('refuses factor attempts made under a lock without counting or renewing it', async () => {
    for (let i = 0; i < 4; i++) await throttle.gateFactor('acct', rule);

    for (let i = 0; i < 12; i++)
      expect(await throttle.gateFactor('acct', rule)).toEqual({ allowed: false });

    expect((await counters.get('acct:2fa:acct'))?.count).toBe(4);
  });

  it('locks once when racing factor attempts get past the lock read, even across a second crossing', async () => {
    staleLockReads();

    const until = clock.now() + 5 * MIN;

    const gates = [];

    for (let i = 0; i < 8; i++) gates.push(await throttle.gateFactor('acct', rule));

    expect(gates.slice(3, 8)).toEqual([
      { allowed: false, newLock: { until } },
      { allowed: false },
      { allowed: false },
      { allowed: false },
      // The second crossing finds the lock running: no new lock, no tier step.
      { allowed: false },
    ]);

    expect((await counters.get('tier:2fa:acct'))?.count).toBe(1);
    expect((await counters.get('acct:2fa:acct'))?.count).toBe(8);
  });

  it('raises the tier once per lock when a parallel burst crosses the limit many times', async () => {
    const strict = new Throttle(counters, clock, {
      perAccount: { limit: 3, window: '15m' },
      perAccountIp: { limit: 1000, window: '15m' },
    });

    staleLockReads();

    const gates = await Promise.all(
      Array.from({ length: 200 }, (_, i) => strict.gateLogin(victim, `ip-${i}`)),
    );

    expect(gates.filter((g) => g.allowed)).toHaveLength(3);

    expect(gates.filter((g) => !g.allowed && g.newLock)).toEqual([
      { allowed: false, reason: 'locked', newLock: { until: clock.now() + 5 * MIN } },
    ]);

    expect((await counters.get(`tier:${victim}`))?.count).toBe(1);
  });

  it('locks the password once when racing logins get past the lock read', async () => {
    const strict = new Throttle(counters, clock, {
      perAccount: { limit: 3, window: '15m' },
      perAccountIp: { limit: 100, window: '15m' },
    });

    staleLockReads();

    const until = clock.now() + 5 * MIN;
    const gates = [];

    for (let i = 0; i < 5; i++) gates.push(await strict.gateLogin(victim, `ip-${i}`));

    expect(gates.slice(3)).toEqual([
      { allowed: false, reason: 'locked', newLock: { until } },
      { allowed: false, reason: 'locked' },
    ]);
  });

  it('touches the lock only on the attempts that cross the limit', async () => {
    const strict = new Throttle(counters, clock, {
      perAccount: { limit: 3, window: '15m' },
      perAccountIp: { limit: 100, window: '15m' },
    });

    staleLockReads();

    const increment = counters.increment.bind(counters);
    const lockWrites: string[] = [];

    counters.increment = (key, windowMs) => {
      if (key.startsWith('lock:')) lockWrites.push(key);

      return increment(key, windowMs);
    };

    // Login: counts 4 and 8 cross; 5 to 7 and 9 to 10 do not.
    for (let i = 0; i < 10; i++) await strict.gateLogin(victim, `ip-${i}`);

    // Factor: counts 4 and 8 cross.
    for (let i = 0; i < 9; i++) await throttle.gateFactor('acct', rule);

    expect(lockWrites).toEqual([
      `lock:${victim}`,
      `lock:${victim}`,
      'lock:2fa:acct',
      'lock:2fa:acct',
    ]);
  });
});

describe('a failure recorded outside login', () => {
  it('locks only once the account-wide budget is spent, and once per lock', async () => {
    const t = new Throttle(counters, clock, { perAccount: { limit: 3, window: '15m' } });

    for (let i = 0; i < 3; i++) expect(await t.recordFailure(victim)).toEqual({});

    expect(await counters.get(`lock:${victim}`)).toBeNull();
    expect(await t.recordFailure(victim)).toEqual({ newLock: { until: clock.now() + 5 * MIN } });

    // Four more cross the limit again under the same lock: counted, not reported, no tier step.
    for (let i = 0; i < 4; i++) expect(await t.recordFailure(victim)).toEqual({});

    expect((await counters.get(`acct:${victim}`))?.count).toBe(8);
    expect((await counters.get(`tier:${victim}`))?.count).toBe(1);
  });
});

describe('permanent tier', () => {
  const small = { perAccount: { limit: 1, window: '15m' }, permanent: { afterLocks: 1 } } as const;

  /** Two attempts from fresh sources: the second crosses the limit of 1. */
  async function lockOnce(t: Throttle) {
    await t.gateLogin(victim, 'a');

    return t.gateLogin(victim, 'b');
  }

  it('escalates the lock after `afterLocks` and holds it past the quiet period', async () => {
    const t = new Throttle(counters, clock, small);

    expect(await lockOnce(t)).toMatchObject({ reason: 'locked', newLock: {} });
    clock.advance(5 * MIN);

    expect(await lockOnce(t)).toMatchObject({
      reason: 'permanently_locked',
      newLock: { permanent: true },
    });

    clock.advance(30 * 24 * 60 * MIN);

    expect(await t.gateLogin(victim, 'c')).toEqual({
      allowed: false,
      reason: 'permanently_locked',
    });

    expect(await t.lockState(victim)).toEqual({ locked: true, permanent: true, until: null });
  });

  it('never escalates a second-factor lock, whatever its scope', async () => {
    const t = new Throttle(counters, clock, small);
    const rule = { limit: 1, window: '15m' } as const;

    for (let round = 0; round < 4; round++) {
      await t.gateFactor(victim, rule);
      expect((await t.gateFactor(victim, rule)).allowed).toBe(false);
      clock.advance(60 * MIN);
    }

    expect((await t.gateFactor(victim, rule)).allowed).toBe(true);
    expect((await t.gateLogin(victim, 'a')).allowed).toBe(true);
  });

  it('escalates a lock reached through recordFailure (a wrong current password)', async () => {
    const t = new Throttle(counters, clock, small);

    await lockOnce(t);
    clock.advance(5 * MIN);
    await t.recordFailure(victim);

    expect(await t.recordFailure(victim)).toEqual({
      newLock: { until: LOCKOUT_EXPIRES_AT, permanent: true },
    });
  });

  it('announces a permanent lock once, however often failures cross the limit under it', async () => {
    const t = new Throttle(counters, clock, small);

    await lockOnce(t);
    clock.advance(5 * MIN);
    await lockOnce(t);

    // Wrong passwords let through by a device token keep crossing, lock after lock.
    for (let round = 0; round < 3; round++) {
      clock.advance(60 * MIN);
      await t.deviceFailed(victim);
      expect(await t.deviceFailed(victim)).toEqual({});
    }

    expect((await t.lockState(victim)).permanent).toBe(true);
  });

  it('reads no permanent marker while the tier is off', async () => {
    const get = vi.spyOn(counters, 'get');

    await throttle.gateLogin(victim, 'a');
    expect(get.mock.calls.map(([key]) => key.split(':')[0])).toEqual(['lock']);
  });

  it('clearPermanent lifts every lock and the backoff, and reports what it found', async () => {
    const t = new Throttle(counters, clock, small);

    await lockOnce(t);
    clock.advance(5 * MIN);
    await lockOnce(t);

    expect(await t.clearPermanent(victim)).toEqual({ locked: true, permanent: true, until: null });

    // A fresh budget and the first tier again: one allowed attempt, then a 5 minute lock.
    expect(await lockOnce(t)).toEqual({
      allowed: false,
      reason: 'locked',
      newLock: { until: clock.now() + 5 * MIN },
    });
  });
});
