/**
 * Upgrading a password hash made with older parameters, after a login proved
 * the password.
 */
import type { AuthCore } from '../core/auth-core';
import { normalizePassword } from '../password/policy';
import type { AuthUser } from '../ports/stores';
import { describeError } from '../shared/describe-error';
import type { RequestMeta } from '../shared/meta';

/** A failure only costs the upgrade, never the login. */
export async function rehash<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
  previous: string,
  password: string,
  meta: RequestMeta,
) {
  try {
    const hash = await core.hasher.hash(normalizePassword(password));

    // Compare-and-set: a password change or reset that landed while this hash
    // was computed must win, or the old password would come back.
    if (await core.users.setPasswordHash(userId, hash, { expected: previous })) {
      await core.emit({ type: 'password.rehashed', userId }, meta);
    }
  } catch (error) {
    core.logger.warn('Password rehash failed', { userId, error: describeError(error) });
  }
}
