/**
 * Completing a password reset.
 *
 * Applying a reset (from a link, or from the ticket a verified code was
 * exchanged for) peeks the token first, so a password that fails the policy
 * does not burn it, then hashes, then consumes it atomically, so of two
 * concurrent resets exactly one writes. A completed reset revokes every
 * session, voids every outstanding reset token, lifts the lockout (the mailbox
 * was proved) and, by default, marks the address verified.
 */
import { PURPOSE, RESET_PURPOSES, type FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
import { normalizeEmail, type NormalizedEmail } from '../shared/email';
import { fail, ok, type AuthErrorCode, type AuthFailure, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/counter-keys';

/** Exchanges a correct reset code for a short-lived ticket that `resetPassword` accepts. */
export async function verifyPasswordResetCode<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { email: string; code: string; meta: RequestMeta },
): Promise<AuthResult<{ ticket: string; expiresAt: number }>> {
  const { meta } = input;
  const limited = await core.rateLimit('password-reset-code', meta.ip, meta);

  if (limited) return limited;

  const email = normalizeEmail(input.email);

  // Guesses are also counted per address, whether or not it has an account or
  // a code outstanding, so spreading guesses over many IPs does not help.
  const perAddress = await core.rateLimit(
    'password-reset-code-address',
    accountKey(email ?? input.email),
    meta,
  );

  if (perAddress) return perAddress;

  const user = await core.users.findCredentialByEmail(email ?? ('' as NormalizedEmail));

  const redemption = await core.tokens.redeemCode(
    PURPOSE.passwordReset,
    user?.id ?? null,
    input.code,
    settings.reset.maxAttempts,
  );

  if (redemption.status !== 'valid') {
    await core.emit(
      {
        type: 'password.reset_code_failed',
        ...(redemption.status === 'unknown' ? {} : { userId: redemption.namedUserId }),
        reason: redemption.status,
      },
      meta,
    );

    return fail('invalid_token', `reset_code_${redemption.status}`);
  }

  const ticket = await core.tokens.issueLink(
    PURPOSE.passwordResetTicket,
    redemption.userId,
    settings.reset.ticketTtlMs,
  );

  await core.emit({ type: 'password.reset_code_verified', userId: redemption.userId }, meta);

  return ok({ ticket: ticket.token, expiresAt: ticket.expiresAt });
}

export async function resetPassword<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { token: string; password: string; secondFactor?: string; meta: RequestMeta },
): Promise<AuthResult<void>> {
  const { meta } = input;
  const limited = await core.rateLimit('password-reset', meta.ip, meta);

  if (limited) return limited;

  const purpose =
    settings.reset.kind === 'code' ? PURPOSE.passwordResetTicket : PURPOSE.passwordReset;

  const peek = await core.tokens.peekLink(purpose, input.token);

  if (peek.status !== 'valid')
    return failed(
      core,
      peek.status === 'unknown' ? undefined : peek.namedUserId,
      peek.status,
      meta,
    );

  const user = await core.users.findById(peek.userId);

  if (!user) return failed(core, peek.userId, 'user_missing', meta);

  for (const hook of core.hooks.beforePasswordReset) {
    const refusal = await hook({ user, secondFactor: input.secondFactor, meta });

    if (refusal) return failed(core, user.id, refusal.reason, meta, refusal.code);
  }

  const hashed = await core.hashNewPassword(input.password, meta);

  if (!hashed.ok) return hashed;

  const redeemed = await core.tokens.redeemLink(purpose, input.token);

  if (redeemed.status !== 'valid')
    return failed(core, user.id, `lost_race_${redeemed.status}`, meta);
  if (!(await core.users.setPasswordHash(user.id, hashed.value)))
    return failed(core, user.id, 'write_refused', meta);

  await core.revokeAllSessions(user.id, 'password-reset');
  await core.tokens.revokeAll(user.id, RESET_PURPOSES);
  await core.throttle.clearAccount(accountKey(user.email));

  if (settings.reset.markEmailVerified && !user.emailVerified) {
    await core.users.markEmailVerified(user.id, user.email as NormalizedEmail);
  }

  await core.emit({ type: 'password.reset', userId: user.id }, meta);

  await core.mail({
    type: 'password-changed',
    to: user.email,
    userId: user.id,
    at: new Date(core.clock.now()),
  });

  return ok();
}

async function failed<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string | undefined,
  reason: string,
  meta: RequestMeta,
  code: AuthErrorCode = 'invalid_token',
): Promise<AuthFailure> {
  await core.emit({ type: 'password.reset_failed', ...(userId ? { userId } : {}), reason }, meta);

  return fail(code, `reset_${reason}`);
}
