// A084: learning account state from the explicit locked answer.
//
// An app that turns on `revealLocked` answers `account_locked` for a locked
// address. An attacker locks addresses on purpose and reads the answer, its
// retry time or its timing to learn which addresses have accounts, or tries
// to read a lock on an address they never attacked.
//
// Stopped by: throttle/rules.ts (the answer is opt-in, off by default),
//   throttle/throttle.ts (counters keyed on the address, so unknown addresses
//   lock and answer the same), flows/login.ts (the same store calls and the
//   same password verify for a known and an unknown address; a spent
//   per-source budget or a wrong password never reads as locked).
// Learn: Enumeration (/auth/learn/enumeration/), Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import { toPublicError } from '../../src';
import {
  countingHasher,
  EMAIL,
  meta,
  PASSWORD,
  recordStoreCalls,
  registered,
  settled,
} from './support';

const GHOST = 'ghost@example.com';

type Env = Awaited<ReturnType<typeof registered>>;

async function lock(t: Env, email: string) {
  for (let i = 0; i < 11; i++)
    await t.auth.login({ email, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

  await settled();
}

describe('A084: learning account state from the locked answer', () => {
  it('is off by default: a locked account answers like a wrong password', async () => {
    const t = await registered();

    await lock(t, EMAIL);

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(!login.ok && toPublicError(login)).toEqual({ code: 'invalid_credentials' });
  });

  it('with the answer on, a known and an unknown address lock and answer alike, after the same work', async () => {
    const { hasher, verified } = countingHasher();

    const t = await registered({
      throttle: { lockout: { revealLocked: true } },
      password: { hasher, breachCheck: false },
    });

    await lock(t, EMAIL);
    await lock(t, GHOST);

    const { calls } = recordStoreCalls(t.stores);
    const answers = [];
    const callsPer = [];

    for (const email of [EMAIL, GHOST]) {
      const before = calls.length;
      const verifiesBefore = verified.length;
      const login = await t.auth.login({ email, password: PASSWORD, meta: meta('198.51.100.9') });

      answers.push(!login.ok && toPublicError(login));
      callsPer.push({ calls: calls.slice(before), verifies: verified.length - verifiesBefore });
    }

    expect(answers[0]).toEqual(answers[1]);
    expect(answers[0]).toMatchObject({ code: 'account_locked' });
    expect(callsPer[0]).toEqual(callsPer[1]);
    expect(callsPer[0]?.verifies).toBe(1);
  });

  it('never reads an unattacked address as locked, nor a spent per-source budget', async () => {
    const t = await registered({
      throttle: { lockout: { revealLocked: true, perAccountIp: { limit: 2, window: '15m' } } },
    });

    for (let i = 0; i < 3; i++)
      await t.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta('192.0.2.1') });

    const spent = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta('192.0.2.1') });
    const fresh = await t.auth.login({ email: GHOST, password: PASSWORD, meta: meta('192.0.2.2') });

    expect(!spent.ok && toPublicError(spent)).toEqual({ code: 'invalid_credentials' });
    expect(!fresh.ok && toPublicError(fresh)).toEqual({ code: 'invalid_credentials' });
  });
});
