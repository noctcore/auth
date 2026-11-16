/**
 * Checking a request's session: the token is valid and unexpired, every
 * `onSessionValidate` hook accepts it, and (for high-privilege actions) its
 * last credential proof is recent enough.
 */
import type { FlowSettings } from './settings';
import { firstRefusal } from '../core/hooks';
import type { AuthCore } from '../core/auth-core';
import type { Clock } from '../ports/clock';
import type { AuthUser, StoredSession } from '../ports/stores';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';

export async function validateRequest<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { token: string | null | undefined; meta?: RequestMeta; touch?: boolean },
): Promise<AuthResult<StoredSession<A>>> {
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

  return ok(result.session);
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
