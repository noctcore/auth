/**
 * Password reset.
 *
 * The request answers the same for every address and does none of the
 * per-account work on the response path: the lookup, the per-account mail
 * limit and the mail happen in `processPasswordReset`, on your queue or
 * detached in-process.
 *
 * Applying a reset (from a link, or from the ticket a verified code was
 * exchanged for) peeks the token first, so a password that fails the policy
 * does not burn it, then hashes, then consumes it atomically, so of two
 * concurrent resets exactly one writes. A completed reset revokes every
 * session, voids every outstanding reset token, lifts the lockout (the mailbox
 * was proved) and, by default, marks the address verified.
 */
import type { AuthCore } from '../core/auth-core';
import type { PasswordResetJob } from '../core/config';
import { normalizeEmail, type NormalizedEmail } from '../shared/email';
import { fail, ok, type AuthErrorCode, type AuthFailure, type AuthResult } from '../shared/errors';
import { sha256Hex } from '../crypto/hash';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/throttle';
import type { AuthUser } from '../ports/stores';
import { publicUser, PURPOSE, RESET_PURPOSES, type FlowSettings } from './settings';

const DEDUPE_WINDOW_MS = 60_000;

export async function requestPasswordReset<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { email: string; captchaToken?: string; meta: RequestMeta },
): Promise<AuthResult<void>> {
  const { meta } = input;
  const captcha = await core.checkCaptcha('password-reset', input.captchaToken, meta);

  if (captcha) return captcha;

  const limited = await core.rateLimit('password-reset-request', meta.ip, meta);

  if (limited) return limited;

  const email = normalizeEmail(input.email);

  if (!email) return fail('invalid_email', 'invalid_email');

  const bucket = Math.floor(core.clock.now() / DEDUPE_WINDOW_MS);

  const job: PasswordResetJob = {
    email,
    ip: meta.ip,
    dedupeKey: sha256Hex(`password-reset:${email}:${bucket}`),
  };

  if (settings.reset.enqueue) {
    await settings.reset.enqueue(job);
  } else {
    void processPasswordReset(core, settings, job).catch((error: unknown) => {
      core.logger.error('Detached password reset job failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    });
  }

  await core.emit({ type: 'password.reset_requested' }, meta);

  return ok();
}

/** The per-account half of a reset request. Your queue worker calls it with the job. */
export async function processPasswordReset<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  job: PasswordResetJob,
): Promise<void> {
  const meta: RequestMeta = { ip: job.ip };
  const email = normalizeEmail(job.email);
  const credential = email ? await core.users.findCredentialByEmail(email) : null;

  if (!credential) {
    await core.emit({ type: 'password.reset_request_ignored', reason: 'unknown_user' }, meta);

    return;
  }

  const user = publicUser(credential);

  for (const hook of core.hooks.beforePasswordResetRequest) {
    const refusal = await hook({ user });

    if (refusal) {
      await core.emit(
        { type: 'password.reset_request_ignored', userId: user.id, reason: refusal.reason },
        meta,
      );

      return;
    }
  }

  if (await core.rateLimit('password-reset-mail', user.id, meta)) {
    await core.emit(
      { type: 'password.reset_request_ignored', userId: user.id, reason: 'mail_limit' },
      meta,
    );

    return;
  }

  if (settings.reset.kind === 'code') {
    const { code, expiresAt } = await core.tokens.issueCode(
      PURPOSE.passwordReset,
      user.id,
      settings.reset.ttlMs,
      settings.reset.digits,
    );

    await core.mail({
      type: 'password-reset-code',
      to: user.email,
      userId: user.id,
      code,
      expiresAt: new Date(expiresAt),
    });
  } else {
    const url = settings.urls.resetPassword;

    if (!url) throw new Error('urls.resetPassword is required for link resets');

    const { token, expiresAt } = await core.tokens.issueLink(
      PURPOSE.passwordReset,
      user.id,
      settings.reset.ttlMs,
    );

    await core.mail({
      type: 'password-reset',
      to: user.email,
      userId: user.id,
      url: url(token),
      expiresAt: new Date(expiresAt),
    });
  }
}

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
