/**
 * Writing a new password hash, for a reset and a change alike.
 *
 * The reset links and tickets (and an email change started under the old
 * password) are voided BEFORE the write, so a crash or a store error after it
 * can never leave one of them alive to set the password again: the worst a
 * failure leaves is the old password and no link, and the user asks again.
 * They are voided once more after the write, so a link a reset request minted
 * while the write ran does not outlive it either.
 *
 * Once the hash is written the password has changed, so the steps that only
 * tidy up after it (that second sweep, lifting the lockout, marking the address
 * verified) are logged when they fail instead of failing the flow: a flow that
 * answered "failed" for a password that did change would send the user round
 * again with a link that is already spent. Each of them fails closed (a lock
 * that stays, an address left unverified). Ending the sessions is not one of
 * them: a failure there still throws, since a session it could not end may
 * belong to whoever the change was meant to lock out.
 */
import { PASSWORD_PURPOSES } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
import { describeError } from '../shared/describe-error';

/** Voids every password purpose, then writes the hash. False when the store refused the write. */
export async function writePasswordHash<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
  hash: string,
): Promise<boolean> {
  await core.tokens.revokeAll(userId, PASSWORD_PURPOSES);

  return core.users.setPasswordHash(userId, hash);
}

/** The second sweep after the write: a failure is logged, the first sweep already ran. */
export async function revokePasswordTokensAfterWrite<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
): Promise<void> {
  await afterPasswordWrite(core, 'revoke password tokens', userId, () =>
    core.tokens.revokeAll(userId, PASSWORD_PURPOSES),
  );
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
