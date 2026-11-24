/**
 * The lockout after an email revert that could not finish. When the revert
 * link's address has an account again, the account cannot go back to it, so
 * it still names the address the intruder chose. The revert has already
 * removed the password and every session; this marker keeps them out:
 * while it lives, no session is issued for the account (by any flow or
 * plugin, an app's own SSO through `issueSession` included), a reset request
 * for it sends nothing, and a reset link or ticket for it is refused. Every
 * refusal answers like the account's ordinary failure (a wrong password, the
 * uniform reset answer, a dead link), so nothing shows the lockout.
 *
 * It never lapses: the account names the intruder's address until someone
 * moves it, so time alone must not hand that address a working reset. It ends
 * only when the owner's revert finishes (the link is kept alive as long) or
 * when support calls `auth.clearEmailRevertLockout`, which voids that link
 * and the hold on the old address too. The marker and the link
 * are stored with the latest expiry every store can hold (LOCKOUT_EXPIRES_AT),
 * not renewed: a renewal would rely on something running before it lapsed.
 *
 * Guide: Build, "Email change".
 */
import { PURPOSE } from './settings';
import type { AuthCore } from '../core/auth-core';
import { refuse, type HookInput } from '../core/hooks';
import type { AuthUser } from '../ports/stores';
import { LOCKOUT_EXPIRES_AT } from '../shared/duration';
import type { RequestMeta } from '../shared/meta';
import type { OneTimeTokens } from '../tokens/one-time-tokens';

/** Locks the account out; returns the expiry its marker is stored with. */
export async function lockOut<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
): Promise<number> {
  const { expiresAt } = await core.tokens.issueLink(
    PURPOSE.emailRevertLockout,
    userId,
    LOCKOUT_EXPIRES_AT - core.clock.now(),
  );

  return expiresAt;
}

export async function endLockout<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
): Promise<void> {
  await core.tokens.revokeAll(userId, [PURPOSE.emailRevertLockout]);
}

/**
 * Ends a lockout by hand. For support, once the account is back on an
 * address its owner controls (or the old address is free and the owner's
 * revert link can finish instead). Calling it while the account still names
 * the intruder's address hands that address a working password reset.
 *
 * Settling the account by hand also ends what the refused revert kept alive:
 * the owner's revert link (stretched to the lockout's expiry) and the hold on
 * the old address. Left alive, the link would move the account back to the
 * old address, password cleared, whenever that address came free, and while
 * it stayed taken each click would remove the password and lock the account
 * out again.
 */
export async function clearEmailRevertLockout<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { userId: string; meta: RequestMeta },
): Promise<void> {
  await core.tokens.revokeAll(input.userId, [
    PURPOSE.emailRevertLockout,
    PURPOSE.emailRevert,
    PURPOSE.emailReserved,
  ]);

  await core.emit(
    { type: 'email.revert_lockout_cleared', userId: input.userId, data: { review: true } },
    input.meta,
  );
}

/** The core's own refusals for an account in lockout. Run before every other hook. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function lockoutHooks(tokens: OneTimeTokens): HookInput<AuthUser, any> {
  const locked = async (userId: string) =>
    (await tokens.findLive(PURPOSE.emailRevertLockout, userId)) !== null;

  return {
    beforeSessionCreate: async ({ user }) =>
      (await locked(user.id)) ? refuse('email_revert_lockout') : undefined,
    beforePasswordResetRequest: async ({ user }) =>
      (await locked(user.id)) ? refuse('email_revert_lockout') : undefined,
    beforePasswordReset: async ({ user }) =>
      (await locked(user.id)) ? refuse('email_revert_lockout', 'invalid_token') : undefined,
    // A reset page's link check answers what the reset would: a dead link.
    passwordResetRequirements: async ({ user }) =>
      (await locked(user.id)) ? refuse('email_revert_lockout', 'invalid_token') : undefined,
  };
}
