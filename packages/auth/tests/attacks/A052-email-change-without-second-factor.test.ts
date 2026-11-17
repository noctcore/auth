// A052: changing the email of a two-factor account without the factor.
//
// An attacker with the password (and so a fresh session) but not the phone
// moves the account to their address, then disables everything from there.
// With a factor on, the email change must ask for it like a password change does.
//
// Stopped by: plugins/two-factor/hooks.ts (`beforeEmailChange` demands a
//   step-up held by this session or a code with the request), flows/email-change.ts
//   (the hooks run before anything is issued or mailed), plugins/two-factor/step-up.ts
//   (a password re-entry re-issues the session under a new id, with no proof).
// Learn: Email change (/auth/learn/email-change/), Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, PASSWORD, twoFactorApp } from '../two-factor/setup';

const NEW = 'mallory@example.com';

async function freshWithoutStepUp(t: ReturnType<typeof twoFactorApp>) {
  const { secret } = await t.enrolled();
  const passed = await t.passed(secret);

  t.clock.advance(10 * 60_000 + 1);

  const fresh = await t.auth.reauthenticate({
    session: passed.session,
    password: PASSWORD,
    meta: meta(),
  });

  if (!fresh.ok) throw new Error(fresh.reason);

  return { secret, session: fresh.value.session };
}

describe('A052: changing the email of a two-factor account without the factor', () => {
  it('refuses a fresh session with no step-up and no code', async () => {
    const t = twoFactorApp();
    const { session } = await freshWithoutStepUp(t);

    expect(await t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() })).toMatchObject(
      {
        ok: false,
        code: 'second_factor_required',
        reason: 'email_change_second_factor_missing',
      },
    );

    expect(t.mailer.last('email-change-confirm')).toBeUndefined();
  });

  it('refuses a wrong code', async () => {
    const t = twoFactorApp();
    const { session } = await freshWithoutStepUp(t);

    expect(
      await t.auth.requestEmailChange({
        session,
        newEmail: NEW,
        secondFactor: '000000',
        meta: meta(),
      }),
    ).toMatchObject({ ok: false, code: 'invalid_second_factor' });
  });

  it('accepts a code with the request, or a step-up held by the session', async () => {
    const t = twoFactorApp();
    const { session, secret } = await freshWithoutStepUp(t);

    expect(
      (
        await t.auth.requestEmailChange({
          session,
          newEmail: NEW,
          secondFactor: t.codeFor(secret),
          meta: meta(),
        })
      ).ok,
    ).toBe(true);

    expect(t.audit.events.filter((e) => e.type === 'two_factor.verified').at(-1)).toMatchObject({
      data: { action: 'email_change' },
    });

    t.nextStep();

    const stepped = await t.auth.twoFactor.stepUp({
      session,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: meta(),
    });

    expect(stepped.ok).toBe(true);

    expect(
      (await t.auth.requestEmailChange({ session, newEmail: 'grace@example.com', meta: meta() }))
        .ok,
    ).toBe(true);
  });

  it('re-issues the session on confirmation without tripping the enforcement hook', async () => {
    const t = twoFactorApp();
    const { session, secret } = await freshWithoutStepUp(t);

    await t.auth.requestEmailChange({
      session,
      newEmail: NEW,
      secondFactor: t.codeFor(secret),
      meta: meta(),
    });

    const code = t.mailer.last('email-change-confirm')?.code ?? '';
    const confirmed = await t.auth.confirmEmailChangeCode({ session, code, meta: meta() });

    if (!confirmed.ok || !confirmed.value.session) throw new Error('confirm failed');

    expect(confirmed.value.session.session.userId).toBe(session.userId);
    expect(t.audit.events.filter((e) => e.type === 'login.failure')).toEqual([]);
  });
});
