/**
 * What the opt-in permanent lockout tier does beyond refusing the password
 * login: it ends the account's sessions and closes the doors a live session
 * could use to get around it. The marker follows the user id, so these
 * checks hold whatever address the account names.
 *
 * - `trustedDevices` on (the default): the lock deletes every session but
 *   leaves the revocation epoch, so device cookies survive and the owner can
 *   still sign in from a known device. Such a session may reauthenticate and
 *   change the password, but no session may change the email.
 * - `trustedDevices` off: the lock bumps the epoch (every session and device
 *   cookie ends) and every session door is refused: issuing a session by any
 *   path, reauthentication, password change, email change and email
 *   verification, until an admin clears the lock.
 *
 * Guide: Learn, "Brute force and lockout".
 */
import type { AuthCore } from '../core/auth-core';
import { refuse, type HookInput } from '../core/hooks';
import type { AuthUser } from '../ports/stores';
import { fail, type AuthFailure } from '../shared/errors';
import type { Throttle } from '../throttle/throttle';

/** The revocation reason the permanent tier reports to `onSessionsRevoked`. */
export const PERMANENT_LOCK_REVOCATION = 'locked-permanently';

/**
 * The refusal for a door while the account is permanently locked, or null.
 * `email-change` is refused in both modes; `session` (reauthentication,
 * password change, email verification) only with `trustedDevices` off.
 */
export async function permanentLockRefusal<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
  door: 'session' | 'email-change',
): Promise<AuthFailure | null> {
  if (door === 'session' && core.throttle.permanentDevices) return null;
  if (!(await core.throttle.isPermanentlyLocked(userId))) return null;

  return fail('forbidden', 'permanently_locked');
}

/**
 * Ends the account's sessions when the permanent tier locks it: with
 * trusted devices, by deleting them (device cookies survive); without, by
 * bumping the epoch. Either way `onSessionsRevoked` hears about it.
 */
export async function endSessionsForPermanentLock<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
): Promise<void> {
  if (!core.throttle.permanentDevices) {
    await core.revokeAllSessions(userId, PERMANENT_LOCK_REVOCATION);

    return;
  }

  const live = await core.sessions.listActive(userId);

  const ids = await core.sessions.revoke(
    userId,
    live.map((session) => session.id),
  );

  await core.emit(
    { type: 'sessions.revoked', userId, reason: PERMANENT_LOCK_REVOCATION },
    undefined,
  );

  await core.notifyRevoked(userId, ids, PERMANENT_LOCK_REVOCATION);
}

/**
 * With `trustedDevices` off: no session is issued for a permanently locked
 * account, by any flow or plugin (an app's own SSO through `issueSession`
 * included). Run before every other hook.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function permanentLockHooks(throttle: Throttle): HookInput<AuthUser, any> {
  return {
    beforeSessionCreate: async ({ user }) =>
      (await throttle.isPermanentlyLocked(user.id)) ? refuse('permanently_locked') : undefined,
  };
}
