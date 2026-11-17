/**
 * Email verification. The default is an 8-digit code, the form the auth guide
 * prefers: it is typed on the device that started the flow, by a signed-in
 * user, so it is bound to that account's session, and it is bound to the
 * address it was sent to. Links are available for apps that need them.
 *
 * Verifying an address revokes every session of the account and re-issues the
 * current one. That closes account pre-hijacking: someone who registered the
 * address first and kept a session loses it the moment the real owner proves
 * the mailbox.
 */
import { PURPOSE, type FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { IssuedSession } from '../core/plugin-context';
import type { AuthUser, StoredSession } from '../ports/stores';
import { normalizeEmail } from '../shared/email';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import type { TokenRedemption } from '../tokens/one-time-tokens';

/** Issues a verification code or link for the user's current address and mails it. */
export async function sendVerification<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  user: U,
  meta: RequestMeta | undefined,
): Promise<void> {
  const data = { email: user.email };

  if (settings.verification.kind === 'code') {
    const { code, expiresAt } = await core.tokens.issueCode(
      PURPOSE.emailVerification,
      user.id,
      settings.verification.ttlMs,
      settings.verification.digits,
      data,
    );

    core.mail({
      type: 'verify-email',
      to: user.email,
      userId: user.id,
      code,
      expiresAt: new Date(expiresAt),
    });
  } else {
    const url = settings.urls.verifyEmail;

    if (!url) throw new Error('urls.verifyEmail is required for link verification');

    const { token, expiresAt } = await core.tokens.issueLink(
      PURPOSE.emailVerification,
      user.id,
      settings.verification.ttlMs,
      data,
    );

    core.mail({
      type: 'verify-email',
      to: user.email,
      userId: user.id,
      url: url(token),
      expiresAt: new Date(expiresAt),
    });
  }

  await core.emit(
    {
      type: 'email.verification_sent',
      userId: user.id,
      data: { kind: settings.verification.kind },
    },
    meta,
  );
}

/** A signed-in user asks for a new verification mail. Already verified: nothing is sent. */
export async function requestEmailVerification<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<AuthResult<{ sent: boolean }>> {
  const limited = await core.rateLimit(
    'email-verification-request',
    input.session.userId,
    input.meta,
  );

  if (limited) return limited;

  const user = await core.users.findById(input.session.userId);

  if (!user) return fail('session_expired', 'user_missing');
  if (user.emailVerified) return ok({ sent: false });

  await sendVerification(core, settings, user, input.meta);

  return ok({ sent: true });
}

export interface VerifiedEmail<A> {
  /** The caller's session, re-issued; null when the request carried none of this user's. */
  readonly session: IssuedSession<A> | null;
}

/** Verifies a code typed by the signed-in user. */
export async function verifyEmailCode<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { session: StoredSession<A>; code: string; meta: RequestMeta },
): Promise<AuthResult<VerifiedEmail<A>>> {
  const limited = await core.rateLimit('email-verification', input.meta.ip, input.meta);

  if (limited) return limited;

  const redemption = await core.tokens.redeemCode(
    PURPOSE.emailVerification,
    input.session.userId,
    input.code,
    settings.verification.maxAttempts,
  );

  return finish(core, redemption, input.session, input.meta);
}

/**
 * Verifies a link. The click must come from a signed-in session of the same
 * account; otherwise the link is left unspent so the user can sign in and open
 * it again. That keeps the pre-hijacking defence: a squatter's session can
 * never be the one that completes verification.
 */
export async function verifyEmailLink<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { token: string; session: StoredSession<A> | null; meta: RequestMeta },
): Promise<AuthResult<VerifiedEmail<A>>> {
  const limited = await core.rateLimit('email-verification', input.meta.ip, input.meta);

  if (limited) return limited;

  const peek = await core.tokens.peekLink(PURPOSE.emailVerification, input.token);

  if (peek.status === 'valid' && input.session?.userId !== peek.userId) {
    await core.emit(
      { type: 'email.verification_failed', userId: peek.userId, reason: 'session_required' },
      input.meta,
    );

    return fail('session_expired', 'verification_session_required');
  }

  const redemption = await core.tokens.redeemLink(PURPOSE.emailVerification, input.token);

  return finish(core, redemption, input.session, input.meta);
}

async function finish<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  redemption: TokenRedemption,
  current: StoredSession<A> | null,
  meta: RequestMeta,
): Promise<AuthResult<VerifiedEmail<A>>> {
  if (redemption.status !== 'valid') {
    await core.emit(
      {
        type: 'email.verification_failed',
        ...(redemption.status === 'unknown' ? {} : { userId: redemption.namedUserId }),
        reason: redemption.status,
      },
      meta,
    );

    return fail('invalid_token', `verification_${redemption.status}`);
  }

  const user = await core.users.findById(redemption.userId);
  const sentTo = normalizeEmail(redemption.data['email']);

  // The address changed since the mail was sent: the proof is for an old address.
  if (!user || !sentTo || user.email !== sentTo) {
    await core.emit(
      { type: 'email.verification_failed', userId: redemption.userId, reason: 'address_changed' },
      meta,
    );

    return fail('invalid_token', 'verification_address_changed');
  }

  const marked = await core.users.markEmailVerified(user.id, sentTo);

  if (!marked) return fail('invalid_token', 'verification_write_refused');

  // Read live before the revocation: only a session still active, and this
  // user's, is re-issued; anything else gets no session back.
  const live = current?.userId === user.id ? await core.confirmLiveSession(current) : null;

  await core.revokeAllSessions(user.id, 'email-verified');
  await core.emit({ type: 'email.verified', userId: user.id }, meta);

  if (!live) return ok({ session: null });

  const issued = await core.issueSession(
    { ...user, emailVerified: true },
    {
      via: 'email-verified',
      meta,
      inherit: live,
      authenticatedAt: live.authenticatedAt,
    },
  );

  return issued.ok ? ok({ session: issued.value }) : issued;
}
