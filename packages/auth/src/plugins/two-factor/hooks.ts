/**
 * Where the two-factor plugin plugs into the core flows.
 *
 * - `loginChallenge`: a correct password becomes a challenge (challenge.ts).
 * - `beforeSessionCreate`: enforcement. Every session in the library is minted
 *   by `issueSession`, and this hook refuses every one for a user with a
 *   confirmed factor, or one the app requires, unless it is the plugin's own
 *   (`second-factor`) or a re-issue of a session the user already holds
 *   (password change, re-authentication, sign out of other devices, email
 *   verified, email changed; the core refuses those labels unless the call passes that user's
 *   session as `inherit`). So no flow that issues a session, sign-up with
 *   `autoLogin` included, gets past the factor. Before a login challenge
 *   (`beforeChallenge`) it refuses nothing: the challenge is the factor. Plugins are trusted code: one
 *   that issues with `via: 'second-factor'` claims to have checked the factor.
 * - `beforePasswordReset`: a reset of an account with a factor needs a code or
 *   a recovery code before the password is written, so a stolen mailbox alone
 *   cannot take the account. The factor survives the reset.
 * - `passwordResetRequirements`: says so ahead of time, for a reset page that
 *   checks its link on load (`inspectPasswordReset`), so it can show the code
 *   field before the user types a new password.
 * - `beforePasswordChange`: the current password is not enough with a factor
 *   on; it needs a step-up in this session or a code with the request.
 * - `beforeEmailChange`: the same for an email change request, on top of the
 *   core's fresh-auth check, so a stolen session (even with the password)
 *   cannot move the account to a new address without the factor.
 * - `sessionStanding` (only with `enforcement`): the grace or enrollment-only
 *   standing of a required user without a factor, on every request
 *   (enforcement.ts). With `enforcement`, `beforeSessionCreate` refuses only
 *   for a confirmed factor: a required user without one signs in, and the
 *   standing confines the session.
 * - `onSessionsRevoked`: a password change, a reset, revoke-all and the like
 *   also delete the trusted devices (they are already void by the epoch).
 *
 * Guide: Learn, "Second factors".
 */
import { loginChallenge } from './challenge';
import { sessionStanding } from './enforcement';
import { checkProof, parseProof } from './proofs';
import { factorAccount, limitIp, type Runtime } from './runtime';
import { hasStepUp } from './step-up';
import { refuse, type HookInput, type HookResult, type IssueVia } from '../../core/hooks';
import type { AuthUser, StoredSession } from '../../ports/stores';
import type { RequestMeta } from '../../shared/meta';

/** Re-issues of a session the user already holds, and the plugin's own issue. */
const PASSES_ENFORCEMENT: ReadonlySet<IssueVia> = new Set([
  'second-factor',
  'password-change',
  'reauthenticate',
  'revoke-others',
  'email-verified',
  'email-changed',
]);

/** Revocations that leave the user's trusted devices alone: one session ended, nothing was compromised. */
const KEEPS_TRUSTED_DEVICES: ReadonlySet<string> = new Set(['logout', 'revoke-one', 'evicted']);

export function twoFactorHooks(
  runtime: () => Runtime,
  options: { readonly enforced: boolean },
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): HookInput<AuthUser, any> {
  return {
    loginChallenge: (context) => loginChallenge(runtime(), context),
    beforeSessionCreate: ({ user, via, beforeChallenge }) =>
      // Before the challenge the factor is still to come: the challenge is it.
      beforeChallenge ? undefined : enforce(runtime(), user, via),
    // Only with `enforcement`: without it, validation reads nothing extra.
    ...(options.enforced
      ? { sessionStanding: ({ session }) => sessionStanding(runtime(), session) }
      : {}),
    passwordResetRequirements: async ({ user }) => ({
      secondFactor: (await runtime().store.findFactor(user.id))?.confirmed === true,
    }),
    beforePasswordReset: ({ user, secondFactor, meta }) =>
      demandProof(runtime(), user, secondFactor, meta, 'reset'),
    beforePasswordChange: ({ user, session, secondFactor, meta }) =>
      demandStepUp(runtime(), user, session, secondFactor, meta, 'password_change'),
    beforeEmailChange: ({ user, session, secondFactor, meta }) =>
      demandStepUp(runtime(), user, session, secondFactor, meta, 'email_change'),
    onSessionsRevoked: async ({ userId, reason }) => {
      if (!KEEPS_TRUSTED_DEVICES.has(reason)) await runtime().store.deleteTrustedDevices(userId);
    },
  };
}

async function enforce(runtime: Runtime, user: AuthUser, via: IssueVia): Promise<HookResult> {
  if (PASSES_ENFORCEMENT.has(via)) return undefined;

  const factor = await runtime.store.findFactor(user.id);

  if (factor?.confirmed === true) return refusedWithoutFactor(via);

  // With `enforcement`, a required user without a factor still gets a
  // session: validation confines it (grace, then enrollment-only).
  if (!runtime.settings.enforcement && (await runtime.settings.required({ user })))
    return refusedWithoutFactor(via);

  return undefined;
}

const refusedWithoutFactor = (via: IssueVia): HookResult =>
  refuse(`second_factor_required:${via}`, 'second_factor_required');

/** A proof with the request, for a user with a confirmed factor; nothing for one without. */
async function demandProof(
  runtime: Runtime,
  user: AuthUser,
  secondFactor: string | undefined,
  meta: RequestMeta,
  action: string,
): Promise<HookResult> {
  const factor = await runtime.store.findFactor(user.id);

  if (factor?.confirmed !== true) return undefined;
  if (!secondFactor) return refuse(`${action}_second_factor_missing`, 'second_factor_required');

  const limited = await limitIp(runtime, meta);

  if (limited) return refuse(limited.reason, limited.code);

  const check = await checkProof(runtime, {
    userId: user.id,
    account: factorAccount(user.id),
    proof: parseProof(secondFactor),
    blocked: null,
    meta,
  });

  if (!check.ok) return refuse(`${action}_second_factor_${check.reason}`, 'invalid_second_factor');

  await runtime.core.emit(
    { type: 'two_factor.verified', userId: user.id, data: { method: check.kind, action } },
    meta,
  );

  return undefined;
}

/** A step-up already in this session, or a proof with the request. */
async function demandStepUp(
  runtime: Runtime,
  user: AuthUser,
  session: StoredSession<unknown>,
  secondFactor: string | undefined,
  meta: RequestMeta,
  action: 'password_change' | 'email_change',
): Promise<HookResult> {
  if (await hasStepUp(runtime, session)) return undefined;

  return demandProof(runtime, user, secondFactor, meta, action);
}
