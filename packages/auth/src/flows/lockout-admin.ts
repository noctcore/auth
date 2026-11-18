/**
 * The admin side of the login lockout: read an account's lock state and lift
 * it. The permanent tier (`throttle.lockout.permanent`) can only be lifted
 * here; a temporary lock lifts on its own or with a completed password reset,
 * and this lifts it too.
 *
 * Locks are keyed on the normalised address, so an address with no account
 * can be locked and inspected as well. Pass `userId` to target an account by
 * its current address. Call these only from an admin-only route: they answer
 * for any address, so a public route would be an enumeration oracle.
 *
 * Guide: Learn, "Brute force and lockout".
 */
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
import { normalizeEmail } from '../shared/email';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/counter-keys';
import type { LockState } from '../throttle/rules';

/** Which lock: an address, or an account by its current address. */
export type LockTarget = { readonly email: string } | { readonly userId: string };

const UNLOCKED: LockState = { locked: false, permanent: false, until: null };

/** The lockout key and, when the target is an account, its id. */
async function resolve<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  target: LockTarget,
): Promise<{ account: string; userId?: string } | null> {
  if ('userId' in target) {
    const user = await core.users.findById(target.userId);
    const email = user ? normalizeEmail(user.email) : null;

    return user && email ? { account: accountKey(email), userId: user.id } : null;
  }

  const email = normalizeEmail(target.email);

  if (!email) return null;

  const user = await core.users.findCredentialByEmail(email);

  return user ? { account: accountKey(email), userId: user.id } : { account: accountKey(email) };
}

export async function inspectLock<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  target: LockTarget,
): Promise<LockState> {
  const resolved = await resolve(core, target);

  return resolved ? core.throttle.lockState(resolved.account) : UNLOCKED;
}

/**
 * Lifts every lock on the target, the permanent one included, and resets its
 * backoff history. Returns the state it found, and writes an
 * `account.lock_cleared` audit row when there was a lock to lift.
 */
export async function clearLock<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: LockTarget & { readonly meta: RequestMeta },
): Promise<LockState> {
  const resolved = await resolve(core, input);

  if (!resolved) return UNLOCKED;

  const before = await core.throttle.clearPermanent(resolved.account);

  if (before.locked) {
    await core.emit(
      {
        type: 'account.lock_cleared',
        ...(resolved.userId === undefined ? {} : { userId: resolved.userId }),
        data: { permanent: before.permanent },
      },
      input.meta,
    );
  }

  return before;
}
