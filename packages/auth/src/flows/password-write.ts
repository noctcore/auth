/**
 * Writing a new password hash, for a reset and a change alike.
 *
 * The reset links and tickets (and an email change started under the old
 * password) are voided BEFORE the write, so a crash, a store error or a
 * refused write can never leave one of them alive to set the password again:
 * the worst a failure leaves is the old password and no link, and the user
 * asks again.
 *
 * After the write, `closeAfterWrite` voids them once more, so a link a reset
 * request minted while the write ran does not outlive it either, and then
 * ends every session. Both always run: a sweep that fails (it is tried twice)
 * never stops the sessions from ending, since the revocation epoch is what
 * fences an intruder's sessions out. The first failure is handed back, and
 * the flow tells the owner about the write that did happen (the audit event,
 * the "password changed" mail) before it throws it. When the sweep failed
 * twice, a link minted during the write may stay live until it expires.
 *
 * The steps that only tidy up (lifting the lockout, marking the address
 * verified) are logged when they fail instead of failing the flow: a flow
 * that answered "failed" for a password that did change would send the user
 * round again with a link that is already spent. Each of them fails closed (a
 * lock that stays, an address left unverified).
 */
import { PASSWORD_PURPOSES } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { RevocationReason } from '../core/hooks';
import type { AuthUser } from '../ports/stores';
import { describeError } from '../shared/describe-error';

/**
 * Voids every password purpose, then writes the hash. False when the store
 * refused the write.
 *
 * A write that throws may still have committed (the connection dropped after
 * the commit), so the password may have changed. The sessions are then ended
 * as after any write (`closeAfterWrite`, which never throws) before the error
 * is rethrown: ending them when the write did not land costs a sign-in, while
 * keeping them when it did would keep an intruder in. A sweep that throws
 * before the write leaves nothing written, and is rethrown as it is.
 */
export async function writePasswordHash<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
  hash: string,
  reason: RevocationReason,
): Promise<boolean> {
  await core.tokens.revokeAll(userId, PASSWORD_PURPOSES);

  try {
    return await core.users.setPasswordHash(userId, hash);
  } catch (error) {
    const closed = await closeAfterWrite(core, userId, reason);

    // The write's error is the one thrown; this one would be lost with it,
    // and it means sessions may still be alive while the hash may be new.
    if (closed.failed)
      core.logger.error('Closing after a password write that threw failed', {
        userId,
        error: describeError(closed.error),
      });

    throw error;
  }
}

/** What closing after a write left to rethrow: nothing, or its first failure. */
export type CloseResult =
  { readonly failed: false } | { readonly failed: true; readonly error: unknown };

/**
 * After a written hash: voids the password tokens again (tried twice), then
 * ends every session whatever the sweep did. Never throws; the first failure
 * comes back for the flow to throw once the owner has been told.
 */
export async function closeAfterWrite<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
  reason: RevocationReason,
): Promise<CloseResult> {
  let result: CloseResult = { failed: false };

  try {
    await sweepTwice(core, userId);
  } catch (error) {
    result = { failed: true, error };
  }

  try {
    await core.revokeAllSessions(userId, reason);
  } catch (error) {
    if (!result.failed) result = { failed: true, error };
  }

  return result;
}

async function sweepTwice<U extends AuthUser, A>(core: AuthCore<U, A>, userId: string) {
  try {
    await core.tokens.revokeAll(userId, PASSWORD_PURPOSES);
  } catch (error) {
    core.logger.warn('Voiding the password tokens after a write failed, trying again', {
      userId,
      error: describeError(error),
    });

    await core.tokens.revokeAll(userId, PASSWORD_PURPOSES);
  }
}

/** Runs a step that follows a written password; a failure is logged with the user id, never thrown. */
export async function afterPasswordWrite<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  step: string,
  userId: string,
  run: () => Promise<unknown>,
): Promise<void> {
  try {
    await run();
  } catch (error) {
    core.logger.error('Step after a password write failed', {
      step,
      userId,
      error: describeError(error),
    });
  }
}
