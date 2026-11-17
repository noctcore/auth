// A044: resetting the password of a two-factor account without the factor.
//
// An attacker who controls the victim's mailbox requests a reset. If the reset
// writes the new password on the link alone, or turns the factor off, or the
// next login skips the factor, the mailbox has beaten the second factor.
//
// Stopped by: plugins/two-factor/hooks.ts (`beforePasswordReset` demands a TOTP code or a
//   recovery code before the password is written, and counts it in the factor budget),
//   flows/password-reset.ts (the hook runs before the hash and the consume), and the
//   factor is never touched by a reset.
// Learn: Second factors (/auth/learn/second-factors/), Password reset (/auth/learn/password-reset/)
import { describe, expect, it } from 'vitest';

import {
  EMAIL,
  meta,
  NEW_PASSWORD,
  PASSWORD,
  twoFactorApp,
  type TwoFactorApp,
} from '../two-factor/setup';

async function resetLink(t: TwoFactorApp) {
  await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
  await new Promise((resolve) => setTimeout(resolve, 0));

  return (t.mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';
}

describe('A044: resetting the password of a two-factor account without the factor', () => {
  it('refuses a reset without a code and leaves the password and the link alone', async () => {
    const t = twoFactorApp();
    const { userId } = await t.enrolled();
    const token = await resetLink(t);
    const before = await t.stores.users.findCredentialById(userId);
    const reset = await t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta() });

    expect(reset).toMatchObject({ ok: false, code: 'second_factor_required' });

    expect((await t.stores.users.findCredentialById(userId))?.passwordHash).toBe(
      before?.passwordHash,
    );

    const old = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(old.ok && old.value.kind).toBe('challenge');
  });

  it('refuses a wrong code, and guesses lock the factor', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();
    const token = await resetLink(t);

    for (let i = 0; i < 5; i++) {
      const reset = await t.auth.resetPassword({
        token,
        password: NEW_PASSWORD,
        secondFactor: `00000${i}`,
        meta: meta(`198.51.100.${i}`),
      });

      expect(!reset.ok && reset.code).toBe('invalid_second_factor');
    }

    const right = await t.auth.resetPassword({
      token,
      password: NEW_PASSWORD,
      secondFactor: t.codeFor(secret),
      meta: meta(),
    });

    expect(right).toMatchObject({
      ok: false,
      code: 'invalid_second_factor',
      reason: 'reset_reset_second_factor_factor_locked',
    });
  });

  it('keeps the factor through a reset: the next login is still challenged', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();
    const token = await resetLink(t);

    const reset = await t.auth.resetPassword({
      token,
      password: NEW_PASSWORD,
      secondFactor: t.codeFor(secret),
      meta: meta(),
    });

    expect(reset.ok).toBe(true);
    expect((await t.store.findFactor(userId))?.confirmed).toBe(true);
    expect(await t.store.countRecoveryCodes(userId)).toBe(10);

    const login = await t.auth.login({ email: EMAIL, password: NEW_PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind).toBe('challenge');
  });

  it('applies to code-mode resets too', async () => {
    const t = twoFactorApp({}, { passwordReset: { kind: 'code' } });

    await t.enrolled();
    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const code = t.mailer.last('password-reset-code')?.code ?? '';
    const ticket = await t.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() });

    if (!ticket.ok) throw new Error(ticket.reason);

    const reset = await t.auth.resetPassword({
      token: ticket.value.ticket,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!reset.ok && reset.code).toBe('second_factor_required');
  });
});
