/**
 * The admin side of the login lockout: read an account's lock state and lift
 * it. The permanent tier (`throttle.lockout.permanent`) can only be lifted
 * here; a temporary lock lifts on its own or with a completed password reset,
 * and this lifts it too.
 *
 * Temporary locks are keyed on the normalised address, a permanent lock on
 * the account's user id (on the address when it has no account), so an
 * address with no account can be locked and inspected as well. Pass
 * `userId` to target an account by its current address. Call these only from an admin-only route: they answer
 * for any address, so a public route would be an enumeration oracle.
 *
 * Guide: Learn, "Brute force and lockout".
 */
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
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
    const email = user ? core.normalizeEmail(user.email) : null;

    return user && email ? { account: accountKey(email), userId: user.id } : null;
  }

  const email = core.normalizeEmail(target.email);

  if (!email) return null;

  const user = await core.findCredentialByEmail(email);

  return user ? { account: accountKey(email), userId: user.id } : { account: accountKey(email) };
}

export async function inspectLock<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  target: LockTarget,
): Promise<LockState> {
  const resolved = await resolve(core, target);

  return resolved ? core.throttle.lockState(resolved.account, resolved.userId) : UNLOCKED;
}

/**
 * Lifts every lock on the target, the permanent one included, and resets its
 * backoff history. Returns the state it found, and writes an
 * `account.lock_cleared` audit row when there was a lock to lift. Not atomic
 * against a burst of failures running meanwhile, which can lock it again.
 */
export async function clearLock<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: LockTarget & { readonly meta: RequestMeta },
): Promise<LockState> {
  const resolved = await resolve(core, input);

  if (!resolved) return UNLOCKED;

  const before = await core.throttle.clearPermanent(resolved.account, resolved.userId);

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
