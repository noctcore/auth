// A046: confirming an enrollment with a wrong or stale code.
//
// Enrollment activates whatever secret it confirms. A secret activated without
// a code from it (or with a code from another secret, or long after it was
// shown) can lock the owner out, or activate a secret an attacker planted from
// a session they briefly held.
//
// Stopped by: plugins/two-factor/enrollment.ts (needs a fresh credential proof; the secret
//   stays pending until a code from it, within the drift window, is confirmed within 10
//   minutes by a compare-and-set on that very secret; guesses spend the factor budget).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { totpCode } from '../../src/plugins/two-factor/totp';
import { EMAIL, meta, PASSWORD, twoFactorApp } from '../two-factor/setup';

describe('A046: confirming an enrollment with a wrong or stale code', () => {
  it('refuses a wrong code, and the secret guards nothing', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const wrong = t.codeFor(started.value.secret) === '123456' ? '654321' : '123456';

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: wrong,
      meta: meta(),
    });

    expect(confirmed).toMatchObject({
      ok: false,
      code: 'invalid_second_factor',
      reason: 'wrong_code',
    });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind).toBe('session');
  });

  it('refuses a code outside the drift window', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    for (const steps of [-2, 2]) {
      const confirmed = await t.auth.twoFactor.confirmEnrollment({
        session,
        code: t.codeFor(started.value.secret, steps),
        meta: meta(),
      });

      expect(!confirmed.ok && confirmed.reason).toBe('wrong_code');
    }
  });

  it('refuses a right code once the pending secret is older than 10 minutes', async () => {
    const t = twoFactorApp({}, { session: { freshAuthAge: '1h' } });
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    t.clock.advance(10 * 60_000);

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    expect(!confirmed.ok && confirmed.reason).toBe('no_pending_enrollment');
  });

  it('refuses a code from a secret replaced by a later enrollment', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const first = await t.auth.twoFactor.enroll({ session, meta: meta() });

    await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!first.ok) throw new Error(first.reason);

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(first.value.secret),
      meta: meta(),
    });

    expect(!confirmed.ok && confirmed.reason).toBe('wrong_code');
  });

  it('locks enrollment guesses like any other code', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const secret = started.value.secret;

    for (let i = 0; i < 5; i++)
      await t.auth.twoFactor.confirmEnrollment({
        session,
        code: totpCode(new Uint8Array(20), i),
        meta: meta(),
      });

    const right = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(secret),
      meta: meta(),
    });

    expect(!right.ok && right.reason).toBe('factor_locked');
  });

  it('needs a fresh credential proof: a stolen old session cannot plant a secret', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    t.clock.advance(60 * 60_000);

    expect(await t.auth.twoFactor.enroll({ session, meta: meta() })).toMatchObject({
      ok: false,
      code: 'fresh_auth_required',
    });
  });
});
