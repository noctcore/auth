/**
 * Checking a request's session: the token is valid and unexpired, every
 * `onSessionValidate` hook accepts it, every `sessionStanding` hook adds its
 * standing for this request, and (for high-privilege actions) its last
 * credential proof is recent enough.
 */
import type { FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import {
  firstRefusal,
  type SessionStanding,
  type TwoFactorStanding,
  type ValidatedSession,
} from '../core/hooks';
import type { Clock } from '../ports/clock';
import type { AuthUser, StoredSession } from '../ports/stores';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';

export async function validateRequest<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { token: string | null | undefined; meta?: RequestMeta; touch?: boolean },
): Promise<AuthResult<ValidatedSession<A>>> {
  const result = await core.sessions.validate(input.token, { touch: input.touch ?? true });

  if (!result.ok) return fail('session_expired', `session_${result.reason}`);

  const refusal = await firstRefusal(core.hooks.onSessionValidate, {
    session: result.session,
    meta: input.meta,
  });

  if (refusal) {
    const ids = await core.sessions.revoke(result.session.userId, [result.session.id]);

    await core.emit(
      { type: 'session.revoked', userId: result.session.userId, reason: refusal.reason },
      input.meta,
    );

    await core.notifyRevoked(result.session.userId, ids, refusal.reason);

    return fail(
      refusal.code === 'invalid_credentials' ? 'session_expired' : refusal.code,
      refusal.reason,
    );
  }

  const standing = await standingOf(core, result.session, input.meta);

  return ok(standing ? { ...result.session, ...standing } : result.session);
}

/**
 * Whether the response to a request should clear its session cookie, given
 * what `validateRequest` answered for the token: true when the token was
 * refused for good, false when it was accepted or refused only because
 * another request may still be adopting it from the app's own store
 * (`adoptLegacySessions`), so the next request can find the adopted session.
 * The adapters clear the cookie through this one check so they cannot drift.
 */
export function clearsSessionCookie(result: AuthResult<unknown>): boolean {
  return !result.ok && result.reason !== 'session_adopting';
}

/** Restrictiveness of each two-factor state: a later hook can tighten it, never loosen it. */
const TWO_FACTOR_RANK: Readonly<Record<TwoFactorStanding['state'], number>> = {
  grace: 1,
  'enrollment-only': 2,
};

/** Every `sessionStanding` hook's answer, merged; null when none added anything. */
async function standingOf<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  session: StoredSession<A>,
  meta: RequestMeta | undefined,
): Promise<SessionStanding | null> {
  let twoFactor: TwoFactorStanding | undefined;

  for (const hook of core.hooks.sessionStanding) {
    const next = (await hook({ session, meta }))?.twoFactor;

    if (next && (!twoFactor || TWO_FACTOR_RANK[next.state] > TWO_FACTOR_RANK[twoFactor.state]))
      twoFactor = next;
  }

  return twoFactor ? { twoFactor } : null;
}

/** Refuses when the session's last credential proof is older than `freshAuthAge`. */
export function requireFreshAuth<A>(
  core: { readonly clock: Clock },
  settings: FlowSettings,
  session: StoredSession<A>,
): AuthResult<void> {
  return core.clock.now() - session.authenticatedAt <= settings.freshAuthAgeMs
    ? ok()
    : fail('fresh_auth_required', 'stale_authentication');
}
