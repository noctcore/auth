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
 * It ends when the owner's revert finishes (the link is kept alive as long as
 * the lockout), when support calls `auth.clearEmailRevertLockout`, or after
 * 90 days.
 *
 * Guide: Build, "Email change".
 */
import { PURPOSE } from './settings';
import type { AuthCore } from '../core/auth-core';
import { refuse, type HookInput } from '../core/hooks';
import type { AuthUser } from '../ports/stores';
import type { RequestMeta } from '../shared/meta';
import type { OneTimeTokens } from '../tokens/one-time-tokens';

/** How long a lockout lasts unless the revert finishes or support clears it first. */
export const REVERT_LOCKOUT_MS = 90 * 24 * 60 * 60_000;

/** Locks the account out; returns when the lockout ends. */
export async function lockOut<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
): Promise<number> {
  const { expiresAt } = await core.tokens.issueLink(
    PURPOSE.emailRevertLockout,
    userId,
    REVERT_LOCKOUT_MS,
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
 */
export async function clearEmailRevertLockout<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { userId: string; meta: RequestMeta },
): Promise<void> {
  await endLockout(core, input.userId);

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
  };
}
