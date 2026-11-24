/**
 * Completing a password reset, and checking a reset link before it is used.
 *
 * Applying a reset (from a link, or from the ticket a verified code was
 * exchanged for) peeks the token first, so a password that fails the policy
 * does not burn it, then checks the new password against the policy (before
 * the hooks, so a refused password spends nothing a hook asked for), runs the
 * hooks and only then hashes (so a refusal costs no hash, like a dead link),
 * then consumes it atomically, so of two
 * concurrent resets exactly one writes. Every outstanding reset token is voided
 * before the write (password-write.ts). A completed reset revokes every
 * session, lifts the lockout (the mailbox was proved) and, by default, marks
 * the address verified; once the password is written, a failure to lift the
 * lock or mark the address is logged and the reset still answers ok.
 */
import { afterPasswordWrite, closeAfterWrite, writePasswordHash } from './password-write';
import { PURPOSE, type FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import { mailMeta } from '../ports/mail';
import type { AuthUser } from '../ports/stores';
import type { NormalizedEmail } from '../shared/email';
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

  const email = core.normalizeEmail(input.email);

  // Guesses are also counted per address, whether or not it has an account or
  // a code outstanding, so spreading guesses over many IPs does not help.
  const perAddress = await core.rateLimit(
    'password-reset-code-address',
    accountKey(email ?? input.email),
    meta,
  );

  if (perAddress) return perAddress;

  const user = await core.findCredentialByEmail(email ?? ('' as NormalizedEmail));

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

/**
 * A live reset link (or ticket), as `inspectPasswordReset` found it. Anyone
 * holding the link sees it, so it names the account by id and address only,
 * never the rest of your user type.
 */
export interface PasswordResetInspection {
  /** The account the link resets. */
  readonly userId: string;
  /** Its address, for "choose a new password for ada@example.com". */
  readonly email: string;
  /** When the link (or ticket) stops working, in ms since the epoch. */
  readonly expiresAt: number;
  /**
   * `resetPassword` will refuse this reset without a `secondFactor`: show the
   * code field with the new password. From the `passwordResetRequirements`
   * hooks (the two-factor plugin answers it for a confirmed factor).
   */
  readonly secondFactorRequired: boolean;
}

/**
 * Checks a reset link (a ticket in code mode) when the reset page loads,
 * without spending it and without mailing anything: an unknown, expired or
 * spent link gets its own page, and an account whose reset will ask for a
 * second factor gets the code field up front. Counted on the same
 * `password-reset` door as `resetPassword`, so checking a link gives no more
 * guesses than applying it. Unknown, expired and spent links answer the same
 * `invalid_token`.
 */
export async function inspectPasswordReset<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { token: string; meta: RequestMeta },
): Promise<AuthResult<PasswordResetInspection>> {
  const { meta } = input;
  const limited = await core.rateLimit('password-reset', meta.ip, meta);

  if (limited) return limited;

  const peek = await core.tokens.peekLink(resetPurpose(settings), input.token);

  if (peek.status !== 'valid')
    return inspectFailed(
      core,
      peek.status === 'unknown' ? undefined : peek.namedUserId,
      peek.status,
      meta,
    );

  const user = await core.users.findById(peek.userId);

  if (!user) return inspectFailed(core, peek.userId, 'user_missing', meta);

  let secondFactorRequired = false;

  for (const hook of core.hooks.passwordResetRequirements) {
    const needs = await hook({ user });

    if (needs && 'refuse' in needs)
      return inspectFailed(core, user.id, needs.reason, meta, needs.code);

    if (needs?.secondFactor === true) secondFactorRequired = true;
  }

  await core.emit({ type: 'password.reset_inspected', userId: user.id }, meta);

  return ok({
    userId: user.id,
    email: user.email,
    expiresAt: peek.expiresAt,
    secondFactorRequired,
  });
}

export async function resetPassword<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { token: string; password: string; secondFactor?: string; meta: RequestMeta },
): Promise<AuthResult<void>> {
  const { meta } = input;
  const limited = await core.rateLimit('password-reset', meta.ip, meta);

  if (limited) return limited;

  const purpose = resetPurpose(settings);
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

  // The new password is checked before the hooks, so one the policy refuses
  // does not spend what a hook asked for (a second factor's code, say), and
  // hashed after them, so a refusal (a lockout, say) costs no hash.
  const checked = await core.checkNewPassword(input.password, meta);

  if (!checked.ok) return checked;

  for (const hook of core.hooks.beforePasswordReset) {
    const refusal = await hook({ user, secondFactor: input.secondFactor, meta });

    if (refusal) return failed(core, user.id, refusal.reason, meta, refusal.code);
  }

  const hashed = await core.hashCheckedPassword(checked.value);

  const redeemed = await core.tokens.redeemLink(purpose, input.token);

  if (redeemed.status !== 'valid')
    return failed(core, user.id, `lost_race_${redeemed.status}`, meta);

  // Every reset link and ticket dies before the write (password-write.ts).
  const written = await writePasswordHash(core, user.id, hashed);

  if (!written) return failed(core, user.id, 'write_refused', meta);

  // The sessions end even when the sweep fails; a failure of either is
  // thrown at the end, once the owner has been told (password-write.ts).
  const closed = await closeAfterWrite(core, user.id, 'password-reset');

  // The password has changed: a failure from here on is logged, not answered.
  await afterPasswordWrite(core, 'lift lockout', user.id, () =>
    core.throttle.clearAccount(accountKey(user.email)),
  );

  if (settings.reset.markEmailVerified && !user.emailVerified) {
    await afterPasswordWrite(core, 'mark email verified', user.id, () =>
      core.users.markEmailVerified(user.id, user.email as NormalizedEmail),
    );
  }

  await core.emit({ type: 'password.reset', userId: user.id }, meta);

  core.mail({
    type: 'password-changed',
    to: user.email,
    userId: user.id,
    at: new Date(core.clock.now()),
    ...mailMeta(meta),
  });

  if (closed.failed) throw closed.error;

  return ok();
}

/** What a reset is applied with: the link in link mode, the ticket a code bought in code mode. */
function resetPurpose(settings: FlowSettings): string {
  return settings.reset.kind === 'code' ? PURPOSE.passwordResetTicket : PURPOSE.passwordReset;
}

async function inspectFailed<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string | undefined,
  reason: string,
  meta: RequestMeta,
  code: AuthErrorCode = 'invalid_token',
): Promise<AuthFailure> {
  await core.emit(
    { type: 'password.reset_inspect_failed', ...(userId ? { userId } : {}), reason },
    meta,
  );

  return fail(code, `reset_${reason}`);
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
