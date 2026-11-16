/**
 * Asking for a password reset.
 *
 * The request answers the same for every address and does none of the
 * per-account work on the response path: the lookup, the per-account mail
 * limit and the mail happen in `processPasswordReset`, on your queue or
 * detached in-process.
 */
import { publicUser, PURPOSE, type FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { PasswordResetJob } from '../core/config';
import { sha256Hex } from '../crypto/hash';
import type { AuthUser } from '../ports/stores';
import { describeError } from '../shared/describe-error';
import { normalizeEmail } from '../shared/email';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';

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

  // One job per address per minute, so a burst of requests sends one mail.
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
        error: describeError(error),
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
    await ignored(core, undefined, 'unknown_user', meta);

    return;
  }

  const user = publicUser(credential);

  for (const hook of core.hooks.beforePasswordResetRequest) {
    const refusal = await hook({ user });

    if (refusal) {
      await ignored(core, user.id, refusal.reason, meta);

      return;
    }
  }

  if (await core.rateLimit('password-reset-mail', user.id, meta)) {
    await ignored(core, user.id, 'mail_limit', meta);

    return;
  }

  if (settings.reset.kind === 'code') await mailResetCode(core, settings, user);
  else await mailResetLink(core, settings, user);
}

/** The audit row for a reset request that sends nothing; the client was answered already. */
async function ignored<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string | undefined,
  reason: string,
  meta: RequestMeta,
): Promise<void> {
  await core.emit(
    { type: 'password.reset_request_ignored', ...(userId ? { userId } : {}), reason },
    meta,
  );
}

async function mailResetCode<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  user: U,
): Promise<void> {
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
}

async function mailResetLink<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  user: U,
): Promise<void> {
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
