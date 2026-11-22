// The doors that prove the current password from a live session
// (`reauthenticate` and `changePassword`) spend login's lockout budget: the
// same per (account, IP) and account-wide counters before the lock, and under
// a lock the budget shared by the account's trusted devices, the live session
// standing in for a device. Guesses through login and both doors add up.
import { describe, expect, it } from 'vitest';

import { toPublicError, type AuthFailure, type LockoutOptions } from '../../src';
import type { StoredSession } from '../../src/ports/stores';
import { countingHasher } from '../attacks/support';
import { meta, NEW_PASSWORD, PASSWORD, settled, setup } from './setup';

const EMAIL = 'ada@example.com';
const WRONG = 'wrong passphrase!';
const MIN = 60_000;
const IP = '203.0.113.7';

type App = ReturnType<typeof setup>;
type Session = StoredSession<Record<string, never>>;

/** Proves `password` through one door; returns the failure, or null on success. */
type Door = (
  t: App,
  session: Session,
  password: string,
  ip?: string,
) => Promise<AuthFailure | null>;

const DOORS: Record<'reauthenticate' | 'changePassword', Door> = {
  reauthenticate: async (t, session, password, ip = IP) => {
    const result = await t.auth.reauthenticate({ session, password, meta: meta(ip) });

    return result.ok ? null : result;
  },
  changePassword: async (t, session, password, ip = IP) => {
    const result = await t.auth.changePassword({
      session,
      currentPassword: password,
      newPassword: NEW_PASSWORD,
      meta: meta(ip),
    });

    return result.ok ? null : result;
  },
};

/** Wide door limits, so only the lockout budget decides. */
const OPEN_DOORS = {
  'password-change': { limit: 1000, window: '1m' },
  reauthenticate: { limit: 1000, window: '1m' },
} as const;

function app(lockout: LockoutOptions = {}, extra: Parameters<typeof setup>[0] = {}) {
  return setup({ throttle: { lockout, doors: OPEN_DOORS }, ...extra });
}

/** Locks the account through login: 11 wrong passwords from fresh sources. */
async function lockThroughLogin(t: App) {
  for (let i = 0; i < 11; i++)
    await t.auth.login({ email: EMAIL, password: WRONG, meta: meta(`192.0.2.${i}`) });

  await settled();
}

describe.each(Object.entries(DOORS))('%s spends login’s budget', (_name, door) => {
  it('counts against the per (account, IP) budget login uses', async () => {
    const t = app();
    const { session } = await t.signedInUser(EMAIL, IP);

    for (let i = 0; i < 5; i++)
      expect((await door(t, session, WRONG))?.reason).toBe('wrong_password');

    // The sixth guess from this IP is refused before the verify, right or wrong.
    const refused = await door(t, session, PASSWORD);

    expect(refused?.reason).toBe('account_ip_budget');
    expect(refused && toPublicError(refused)).toEqual({ code: 'invalid_credentials' });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta(IP) });

    expect(!login.ok && login.reason).toBe('account_ip_budget');
  });

  it('adds up with login’s guesses toward the account-wide lock', async () => {
    const t = app();
    const { session } = await t.signedInUser(EMAIL, IP);

    // The sign-in itself spent one attempt of the account-wide budget (10).
    for (let i = 0; i < 4; i++)
      await t.auth.login({ email: EMAIL, password: WRONG, meta: meta(`192.0.2.${i}`) });

    for (let i = 0; i < 5; i++)
      expect((await door(t, session, WRONG, `198.51.100.${i}`))?.reason).toBe('wrong_password');

    // The eleventh guess, through the door, locks the account.
    expect((await door(t, session, PASSWORD, '198.51.100.99'))?.reason).toBe('locked');
    expect(t.mailer.sent.filter((m) => m.type === 'lockout')).toHaveLength(1);

    const login = await t.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('198.51.100.100'),
    });

    expect(!login.ok && login.reason).toBe('locked');
  });

  it('under a lock, checks no more passwords than the trusted-device budget', async () => {
    const t = app();
    const { session } = await t.signedInUser(EMAIL, IP);

    await lockThroughLogin(t);

    let checked = 0;

    for (let i = 0; i < 30; i++) {
      t.clock.advance(30_000);

      if ((await door(t, session, WRONG))?.reason === 'wrong_password') checked++;
    }

    // perDevice defaults to 5 per 15 min, the budget a trusted device gets at
    // login; the lock lapses after 5 min and opens a per (account, IP) budget of 5.
    expect(checked).toBeLessThanOrEqual(10);
  });

  it('refuses the right password under a lock once the device budget is spent', async () => {
    const t = app();
    const { session } = await t.signedInUser(EMAIL, IP);

    await lockThroughLogin(t);

    for (let i = 0; i < 5; i++)
      expect((await door(t, session, WRONG))?.reason).toBe('wrong_password');

    const right = await door(t, session, PASSWORD);

    expect(right?.reason).toBe('device_budget');
    expect(right && toPublicError(right)).toEqual({ code: 'invalid_credentials' });
  });

  it('lets the owner’s correct password through a lock an outsider set', async () => {
    const t = app();
    const { session } = await t.signedInUser(EMAIL, IP);

    await lockThroughLogin(t);

    expect(await door(t, session, PASSWORD)).toBeNull();
  });

  it('answers account_locked under revealLocked, as login does', async () => {
    const t = app({ revealLocked: true, perDevice: { limit: 1, window: '15m' } });
    const { session } = await t.signedInUser(EMAIL, IP);

    await lockThroughLogin(t);
    await door(t, session, WRONG);

    const refused = await door(t, session, PASSWORD);

    expect(refused?.code).toBe('account_locked');
  });

  it('pays for the password verify when the budget refuses, like a wrong password', async () => {
    const { hasher, verified } = countingHasher();

    const t = setup({
      password: { hasher, breachCheck: false },
      throttle: { lockout: { perAccountIp: { limit: 1, window: '15m' } }, doors: OPEN_DOORS },
    });

    const { session } = await t.signedInUser(EMAIL, IP);
    const before = verified.length;

    expect((await door(t, session, WRONG))?.reason).toBe('wrong_password');
    expect((await door(t, session, WRONG))?.reason).toBe('account_ip_budget');
    expect(verified.length - before).toBe(2);
  });
});

describe('the two session doors together', () => {
  it('share one budget under a lock, with login’s trusted devices', async () => {
    const t = app();
    const { session } = await t.signedInUser(EMAIL, IP);

    await lockThroughLogin(t);

    let checked = 0;

    // Fourteen guesses inside the 5 minute lock.
    for (let i = 0; i < 7; i++) {
      t.clock.advance(MIN / 2);

      for (const door of Object.values(DOORS))
        if ((await door(t, session, WRONG))?.reason === 'wrong_password') checked++;
    }

    expect(checked).toBeLessThanOrEqual(5);
  });
});
