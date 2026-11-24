/**
 * Asking for a password reset.
 *
 * The request answers the same for every address and does none of the
 * per-account work on the response path: the lookup, the per-account mail
 * limit and the mail happen in `processPasswordReset`, on your queue or
 * detached in-process. The job carries the request's IP and user agent, so
 * the audit rows and the mail it writes name the request that asked, wherever
 * the job runs.
 */
import { publicUser, PURPOSE, type FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { PasswordResetJob } from '../core/config';
import { sha256Hex } from '../crypto/hash';
import { mailMeta } from '../ports/mail';
import type { AuthUser } from '../ports/stores';
import { ok, type AuthResult } from '../shared/errors';
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

  const parsed = core.parseEmail(input.email);

  if (!parsed.ok) return parsed;

  const email = parsed.value;

  // One job per address per minute, so a burst of requests sends one mail.
  const bucket = Math.floor(core.clock.now() / DEDUPE_WINDOW_MS);

  const job: PasswordResetJob = {
    email,
    ip: meta.ip,
    ...(meta.userAgent === undefined ? {} : { userAgent: meta.userAgent }),
    dedupeKey: sha256Hex(`password-reset:${email}:${bucket}`),
  };

  if (settings.reset.enqueue) {
    await settings.reset.enqueue(job);
  } else {
    // Uncapped, like the other audit-writing work off the response path: every
    // branch of the job writes an audit row, and `maxPending` must not drop
    // it. Only the mail it hands over is a capped task, so a cap drops the
    // mail (logged with the user id), never the row.
    core.background(
      'password reset job',
      () => processPasswordReset(core, settings, job),
      undefined,
      { uncapped: true },
    );
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
  // The request's own meta, carried on the job: the job may run on a queue
  // worker, long after and far from the request.
  const meta: RequestMeta =
    job.userAgent === undefined ? { ip: job.ip } : { ip: job.ip, userAgent: job.userAgent };

  const email = core.normalizeEmail(job.email);
  const credential = email ? await core.findCredentialByEmail(email) : null;

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

  const mailLimited = await core.rateLimit('password-reset-mail', user.id, meta);

  if (mailLimited) {
    await ignored(core, user.id, 'mail_limit', meta);

    return;
  }

  if (settings.reset.kind === 'code') await mailResetCode(core, settings, user, meta);
  else await mailResetLink(core, settings, user, meta);
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
  meta: RequestMeta,
): Promise<void> {
  const { code, expiresAt } = await core.tokens.issueCode(
    PURPOSE.passwordReset,
    user.id,
    settings.reset.ttlMs,
    settings.reset.digits,
  );

  await issued(core, user.id, 'code', meta);

  core.mail({
    type: 'password-reset-code',
    to: user.email,
    userId: user.id,
    code,
    expiresAt: new Date(expiresAt),
    ...mailMeta(meta),
  });
}

async function mailResetLink<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  user: U,
  meta: RequestMeta,
): Promise<void> {
  const url = settings.urls.resetPassword;

  if (!url) throw new Error('urls.resetPassword is required for link resets');

  const { token, expiresAt } = await core.tokens.issueLink(
    PURPOSE.passwordReset,
    user.id,
    settings.reset.ttlMs,
  );

  await issued(core, user.id, 'link', meta);

  core.mail({
    type: 'password-reset',
    to: user.email,
    userId: user.id,
    url: url(token),
    expiresAt: new Date(expiresAt),
    ...mailMeta(meta),
  });
}

/**
 * The audit row for a reset that was sent: the link or code is stored, the
 * mail is about to be handed over. Awaited first, so the row exists before the
 * mail can arrive (a mail dropped or lost after the hand-over still has it).
 */
async function issued<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
  kind: 'link' | 'code',
  meta: RequestMeta,
): Promise<void> {
  await core.emit({ type: 'password.reset_issued', userId, data: { kind } }, meta);
}
