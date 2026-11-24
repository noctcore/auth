// A002: locking the victim out.
//
// Anyone who knows an address fails logins on purpose to keep the owner locked
// out, from one IP or spread over many. Or whoever holds a stolen session
// guesses wrong current passwords at `reauthenticate` and `changePassword`,
// which spend login's budgets, to lock the owner out of sign-in (for good,
// with the permanent tier).
//
// Stopped by: throttle/throttle.ts: a small per-(account, IP) budget, a capped lock with no
//   permanent tier that rises one step per lock (not per request that crosses the limit), and
//   the trusted-device bypass for a correct password;
//   flows/password-reset.ts lifts the lock once the mailbox is proved;
//   flows/password-change.ts with `throttle.lockout.sessionProofs: 'door'` keeps the session
//   doors out of the lockout (opt-in; by default they spend it, see A102).
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { beforeEach, describe, expect, it } from 'vitest';

import { toPublicError, type LockoutOptions } from '../../src';
import { manualClock, MemoryCounterStore, type ManualClock } from '../../src/testing';
import { accountKey } from '../../src/throttle/counter-keys';
import { Throttle } from '../../src/throttle/throttle';
import {
  EMAIL,
  linkFor,
  meta,
  NEW_PASSWORD,
  PASSWORD,
  queued,
  registered,
  settled,
  setup,
} from './support';

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

describe('A002: locking the victim out', () => {
  it('caps one source at 5 attempts per account without locking the owner out from elsewhere', async () => {
    const { auth } = await registered();

    for (let i = 0; i < 5; i++)
      await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta('192.0.2.66') });

    const attacker = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('192.0.2.66'),
    });

    expect(!attacker.ok && attacker.reason).toBe('account_ip_budget');
    expect(!attacker.ok && toPublicError(attacker)).toEqual({ code: 'invalid_credentials' });

    const owner = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('198.51.100.20'),
    });

    expect(owner.ok).toBe(true);
  });

  it('probe A: the owner on a known device signs in every hour while an attacker keeps the account locked', async () => {
    const { auth, clock } = await registered();
    const first = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('203.0.113.5') });

    if (!first.ok || first.value.kind !== 'session') throw new Error('first login failed');

    let deviceToken = first.value.session.deviceCookie.value;

    for (let hour = 0; hour < 24; hour++) {
      for (let i = 0; i < 30; i++)
        await auth.login({
          email: EMAIL,
          password: 'wrong passphrase!',
          meta: meta(`192.0.${hour}.${i}`),
        });

      const stranger = await auth.login({
        email: EMAIL,
        password: PASSWORD,
        meta: meta('198.51.100.20'),
      });

      expect(!stranger.ok && stranger.reason).toBe('locked');

      const owner = await auth.login({
        email: EMAIL,
        password: PASSWORD,
        deviceToken,
        meta: meta('203.0.113.5'),
      });

      if (!owner.ok || owner.value.kind !== 'session')
        throw new Error(`hour ${hour}: owner refused`);

      deviceToken = owner.value.session.deviceCookie.value;
      clock.advance(60 * 60_000);
    }
  });

  it('probe A: the owner signs in every hour while an attacker spreads failures across IPs', async () => {
    let ip = 0;

    for (let hour = 0; hour < 48; hour++) {
      // Thirty failures an hour from thirty fresh IPs keep the account locked for everyone else.
      for (let i = 0; i < 30; i++)
        await throttle.gateLogin(victim, `192.0.2.${ip++ % 250}-${hour}`);

      expect((await throttle.gateLogin(victim, `198.51.100.${hour}`)).allowed).toBe(false);
      const owner = await throttle.gateLogin(victim, '203.0.113.5', 'owner-device');

      expect(owner.allowed).toBe(true);
      await throttle.loginSucceeded(victim, '203.0.113.5', 'owner-device');
      clock.advance(60 * MIN);
    }
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

    expect(first).toEqual({
      allowed: false,
      reason: 'locked',
      newLock: { until: clock.now() + 5 * MIN },
    });

    expect(await throttle.gateLogin(victim, '198.51.100.1')).toEqual({
      allowed: false,
      reason: 'locked',
    });

    clock.advance(5 * MIN);
    const second = await lockFor();

    expect(second).toEqual({
      allowed: false,
      reason: 'locked',
      newLock: { until: clock.now() + 15 * MIN },
    });

    clock.advance(15 * MIN);
    const third = await lockFor();

    expect(third).toEqual({
      allowed: false,
      reason: 'locked',
      newLock: { until: clock.now() + 45 * MIN },
    });

    clock.advance(45 * MIN);
    const fourth = await lockFor();

    expect(fourth).toEqual({
      allowed: false,
      reason: 'locked',
      newLock: { until: clock.now() + 60 * MIN },
    });

    clock.advance(60 * MIN);
    expect((await throttle.gateLogin(victim, '198.51.100.1')).allowed).toBe(true);
  });

  it('raises the lock by one tier per lock, however many requests of a burst cross the limit', async () => {
    // Every request reads "no lock", as a burst that all got past the lock check would.
    const get = counters.get.bind(counters);

    counters.get = (key) => (key.startsWith('lock:') ? Promise.resolve(null) : get(key));

    const burst = () =>
      Promise.all(Array.from({ length: 500 }, (_, i) => throttle.gateLogin(victim, `10.1.${i}`)));

    const first = await burst();

    expect(first.filter((g) => g.allowed)).toHaveLength(10);
    expect(first.filter((g) => !g.allowed && g.newLock)).toHaveLength(1);

    // The next lock is one step up (15 minutes), not the cap the burst would have pushed it to.
    clock.advance(5 * MIN);
    const second = await burst();

    expect(second.filter((g) => !g.allowed && g.newLock)).toEqual([
      { allowed: false, reason: 'locked', newLock: { until: clock.now() + 15 * MIN } },
    ]);
  });

  it('lifts the lockout, since the mailbox was proved', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);

    for (let i = 0; i < 11; i++)
      await t.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });

    await t.auth.resetPassword({ token: await linkFor(t), password: NEW_PASSWORD, meta: meta() });

    expect((await t.auth.login({ email: EMAIL, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );
  });
});

type Proof = 'reauthenticate' | 'changePassword';

/** Proves `password` at a session door; the result's ok and reason. */
async function prove(
  t: Awaited<ReturnType<typeof signedIn>>,
  door: Proof,
  password: string,
  ip = '203.0.113.7',
) {
  const result =
    door === 'reauthenticate'
      ? await t.auth.reauthenticate({ session: t.session, password, meta: meta(ip) })
      : await t.auth.changePassword({
          session: t.session,
          currentPassword: password,
          newPassword: NEW_PASSWORD,
          meta: meta(ip),
        });

  return result.ok ? { ok: true as const } : { ok: false as const, reason: result.reason };
}

/** An owner signed in on an app whose lockout is small enough for a few guesses to lock it. */
async function signedIn(lockout: LockoutOptions, doors: Parameters<typeof setup>[0] = {}) {
  const t = setup({
    throttle: {
      lockout: { perAccount: { limit: 3, window: '15m' }, ...lockout },
      ...doors.throttle,
    },
  });

  const { session } = await t.signedInUser(EMAIL);

  return { ...t, session };
}

describe.each<Proof>(['reauthenticate', 'changePassword'])(
  'A002: locking the owner out through a stolen session at %s',
  (door) => {
    it("by default, wrong current passwords lock sign-in and climb the permanent tier (pinned; 'door' opts out)", async () => {
      const t = await signedIn({ permanent: { afterLocks: 1 } });

      for (let i = 0; i < 3; i++) await prove(t, door, 'wrong passphrase!');

      await settled();

      expect((await t.auth.lockout.inspect({ email: EMAIL })).locked).toBe(true);
      expect(t.mailer.sent.some((m) => m.type === 'lockout')).toBe(true);
    });

    it("with sessionProofs 'door', six wrong passwords lock nothing and the door refuses the sixth", async () => {
      const t = await signedIn({ sessionProofs: 'door', permanent: { afterLocks: 1 } });
      const answers = [];

      for (let i = 0; i < 6; i++) answers.push(await prove(t, door, 'wrong passphrase!'));

      await settled();

      expect(answers.map((a) => a.ok || a.reason)).toEqual([
        ...Array.from({ length: 5 }, () => 'wrong_password'),
        `rate_limited:${door === 'reauthenticate' ? 'reauthenticate' : 'password-change'}`,
      ]);

      expect(await t.auth.lockout.inspect({ email: EMAIL })).toEqual({
        locked: false,
        permanent: false,
        until: null,
      });

      expect(t.mailer.sent.filter((m) => m.type === 'lockout')).toEqual([]);
      expect(t.audit.types().filter((type) => type === 'password.change_failed')).toHaveLength(5);

      // Nothing was counted toward the permanent tier: one lock through login
      // is the first in a row, so it stays temporary.
      for (let i = 0; i < 3; i++)
        await t.auth.login({
          email: EMAIL,
          password: 'wrong passphrase!',
          meta: meta(`192.0.2.${i}`),
        });

      expect(await t.auth.lockout.inspect({ email: EMAIL })).toMatchObject({
        locked: true,
        permanent: false,
      });
    });

    it("with sessionProofs 'door', a correct password goes through a temporary lock whose device budget is spent", async () => {
      const t = await signedIn(
        { sessionProofs: 'door' },
        {
          throttle: {
            doors: {
              'password-change': { limit: 100, window: '1m' },
              reauthenticate: { limit: 100, window: '1m' },
            },
          },
        },
      );

      for (let i = 0; i < 4; i++)
        await t.auth.login({
          email: EMAIL,
          password: 'wrong passphrase!',
          meta: meta(`192.0.2.${i}`),
        });

      expect((await t.auth.lockout.inspect({ email: EMAIL })).locked).toBe(true);

      // Under 'lockout' these would spend the device budget the session stands in for.
      for (let i = 0; i < 6; i++) await prove(t, door, 'wrong passphrase!');

      expect(await prove(t, door, PASSWORD)).toEqual({ ok: true });
    });

    it("with sessionProofs 'door', a permanent lock without trusted devices still refuses", async () => {
      const t = await signedIn({
        sessionProofs: 'door',
        permanent: { afterLocks: 1, trustedDevices: false },
      });

      for (let round = 0; round < 2; round++) {
        for (let i = 0; i < 4; i++)
          await t.auth.login({
            email: EMAIL,
            password: 'wrong passphrase!',
            meta: meta(`192.0.${round}.${i}`),
          });

        t.clock.advance(60 * MIN);
      }

      expect((await t.auth.lockout.inspect({ email: EMAIL })).permanent).toBe(true);
      // The lock bumped the epoch, so the session itself is gone; the door refuses either way.
      expect(await prove(t, door, PASSWORD)).toEqual({ ok: false, reason: 'session_not_active' });
    });
  },
);
