// A002: locking the victim out.
//
// Anyone who knows an address fails logins on purpose to keep the owner locked
// out, from one IP or spread over many.
//
// Stopped by: throttle/throttle.ts: a small per-(account, IP) budget, a capped lock with no
//   permanent tier, and the trusted-device bypass for a correct password;
//   flows/password-reset.ts lifts the lock once the mailbox is proved.
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { beforeEach, describe, expect, it } from 'vitest';

import { toPublicError } from '../../src';
import { manualClock, MemoryCounterStore, type ManualClock } from '../../src/testing';
import { accountKey } from '../../src/throttle/counter-keys';
import { Throttle } from '../../src/throttle/throttle';
import { EMAIL, linkFor, meta, NEW_PASSWORD, PASSWORD, queued, registered } from './support';

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
