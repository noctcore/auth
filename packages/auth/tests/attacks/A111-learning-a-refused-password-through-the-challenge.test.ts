// A111: learning that a refused account's password is right from its
// second-factor challenge.
//
// An app refuses some accounts at sign-in (a removed member, an account
// fenced from this surface) in `beforeSessionCreate`, and every such refusal
// reads like a wrong password. If the second factor's challenge came first,
// whoever holds the password of a refused account would see a challenge, and
// so learn the password is right, before the app refused at the session.
//
// The throttle must not tell either: if a refused right password were
// credited as a success, it would clear the per-address counter that a wrong
// one leaves, and with `revealLocked` the next answer would differ.
//
// Stopped by: flows/login.ts (the `beforeSessionCreate` hooks run, with
//   `beforeChallenge: true`, before any challenge is made; the password is
//   credited to the throttle only once no hook refused, and a refusal counts as a
//   wrong password), core/auth-core.ts (`refuseBeforeChallenge`, and
//   `issueAfterPassword` crediting only after the hooks), plugins/two-factor/hooks.ts
//   (its enforcement refuses nothing before the challenge: the challenge is the factor).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it, vi } from 'vitest';

import { refuse } from '../../src';
import { setup } from '../flows/setup';
import { recordTwoFactorCalls } from '../two-factor/setup';
import { EMAIL, meta, PASSWORD, twoFactorApp } from '../two-factor/setup';

const FENCED = 'fenced@example.com';

/** An app that refuses one account at sign-in once it is fenced, with the default code. */
function fencing() {
  const fence = { on: false };

  return {
    fence,
    overrides: {
      hooks: {
        beforeSessionCreate: ({ user }: { user: { email: string } }) =>
          fence.on && user.email === FENCED ? refuse('fenced_from_portal') : undefined,
      },
    },
  };
}

describe('A111: learning a refused password through the second-factor challenge', () => {
  it('answers a refused account with a factor as a wrong password, with no challenge', async () => {
    const { fence, overrides } = fencing();
    const t = twoFactorApp({}, overrides);

    await t.enrolled(FENCED);
    fence.on = true;

    const right = await t.auth.login({ email: FENCED, password: PASSWORD, meta: meta() });
    const wrong = await t.auth.login({ email: FENCED, password: 'not it', meta: meta() });

    expect(right).toMatchObject({ ok: false, code: 'invalid_credentials' });
    expect(wrong).toMatchObject({ ok: false, code: 'invalid_credentials' });
    expect(t.audit.events.some((e) => e.type === 'login.challenge')).toBe(false);

    const failures = t.audit.events.filter((e) => e.type === 'login.failure');

    expect(failures.at(-2)).toMatchObject({
      reason: 'fenced_from_portal',
      data: { via: 'password' },
    });
  });

  it('makes no challenge and reads no factor for a refused account', async () => {
    const { fence, overrides } = fencing();
    const t = twoFactorApp({}, overrides);

    await t.enrolled(FENCED);
    fence.on = true;

    const calls: string[] = [];

    recordTwoFactorCalls(t.store, calls);

    const tokens = vi.spyOn(t.stores.tokens, 'put');

    await t.auth.login({ email: FENCED, password: PASSWORD, meta: meta() });

    expect(calls).toEqual([]);
    expect(tokens).not.toHaveBeenCalled();
  });

  it('gives an account the hook accepts its challenge as before', async () => {
    const { fence, overrides } = fencing();
    const t = twoFactorApp({}, overrides);

    await t.enrolled(EMAIL);
    fence.on = true;

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind).toBe('challenge');
  });

  it('refuses before an enrollment challenge too, for a required user without a factor', async () => {
    const { fence, overrides } = fencing();
    const t = twoFactorApp({ required: () => true }, overrides);

    fence.on = true;

    await t.auth.register({ email: FENCED, password: PASSWORD, meta: meta() });

    const login = await t.auth.login({ email: FENCED, password: PASSWORD, meta: meta() });

    expect(login).toMatchObject({
      ok: false,
      code: 'invalid_credentials',
      reason: 'fenced_from_portal',
    });
  });

  // 4 wrong from one address, 4 from another, the candidate from the second,
  // then one more wrong from it: a right candidate must leave the same answer
  // as a wrong one.
  async function lastAnswer(withFactor: boolean, candidate: string) {
    const { fence, overrides } = fencing();
    const options = { ...overrides, throttle: { lockout: { revealLocked: true } } };
    const t = withFactor ? twoFactorApp({}, options) : setup(options);

    if (withFactor) await (t as ReturnType<typeof twoFactorApp>).enrolled(FENCED);
    else await t.signedInUser(FENCED);

    fence.on = true;

    const attempt = (password: string, ip: string) =>
      t.auth.login({ email: FENCED, password, meta: meta(ip) });

    for (let i = 0; i < 4; i += 1) await attempt('not it', '198.51.100.2');

    for (let i = 0; i < 4; i += 1) await attempt('not it', '198.51.100.1');

    const answer = await attempt(candidate, '198.51.100.1');

    expect(answer).toMatchObject({ ok: false });

    const last = await attempt('not it', '198.51.100.1');

    return last.ok ? 'ok' : last.code;
  }

  it('leaves the lockout where a wrong password leaves it, with revealLocked', async () => {
    for (const withFactor of [true, false]) {
      const wrong = await lastAnswer(withFactor, 'not it');
      const right = await lastAnswer(withFactor, PASSWORD);

      expect(wrong).toBe('invalid_credentials');
      expect(right).toBe(wrong);
    }
  });

  it('counts a refused correct password through a trusted device, under a lock, as a device failure', async () => {
    const { fence, overrides } = fencing();
    const t = setup(overrides);

    await t.signedInUser(FENCED);
    const first = await t.auth.login({ email: FENCED, password: PASSWORD, meta: meta() });

    if (!first.ok || first.value.kind !== 'session') throw new Error('expected a session');

    const deviceToken = first.value.session.deviceCookie.value;

    // Lock the account from many addresses.
    for (let i = 0; i < 11; i += 1)
      await t.auth.login({ email: FENCED, password: 'not it', meta: meta(`192.0.2.${i}`) });

    fence.on = true;

    const failed = vi.spyOn(t.auth.context.throttle, 'deviceFailed');
    const succeeded = vi.spyOn(t.auth.context.throttle, 'loginSucceeded');

    const refused = await t.auth.login({
      email: FENCED,
      password: PASSWORD,
      deviceToken,
      meta: meta(),
    });

    expect(refused).toMatchObject({ ok: false, code: 'invalid_credentials' });
    expect(failed).toHaveBeenCalledTimes(1);
    expect(succeeded).not.toHaveBeenCalled();
  });
});
