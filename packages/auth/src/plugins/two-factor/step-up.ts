/**
 * Step-up: a sensitive action (turning the factor off, new recovery codes, a
 * password change, an email change request, and whatever the app guards with
 * `requireStepUp`, such as deleting the account) needs a second-factor proof
 * made in this session within the last few minutes, on top of the fresh-auth
 * check. A password change or an email change request also takes a code with
 * the request instead.
 *
 * - The proof is stored per session id, with a server-side expiry; a session
 *   re-issued by a password re-entry gets a new id and so no proof: the
 *   password alone can never mint one.
 * - A trusted device skips the login challenge, never a step-up.
 * - `verifyProof` checks a proof for a user an app flow identified without a
 *   session (an app-owned reset, an invitation that overwrites an account),
 *   on the same per-IP limit, factor budget, replay guard and recovery-code
 *   spend as the challenge, so it is never a faster way to guess codes. With
 *   a proof, a user without a confirmed factor (or no user) answers exactly
 *   like a wrong code, after the same work.
 *
 * Guide: Learn, "Second factors".
 */
import { checkProof, type SecondFactorProof } from './proofs';
import { factorAccount, limitIp, refused, unguardedAccount, type Runtime } from './runtime';
import type { StoredSession } from '../../ports/stores';
import { fail, ok, type AuthResult } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

/** Records a second-factor proof for this session; returns when it lapses. */
export async function recordStepUp(
  runtime: Runtime,
  session: { readonly id: string; readonly userId: string },
): Promise<number> {
  const expiresAt = runtime.core.clock.now() + runtime.settings.stepUpWindowMs;

  await runtime.store.putStepUp({ sessionId: session.id, userId: session.userId, expiresAt });

  return expiresAt;
}

/** Whether this session holds an unexpired proof of its own user. */
export async function hasStepUp(
  runtime: Runtime,
  session: { readonly id: string; readonly userId: string },
): Promise<boolean> {
  const proof = await runtime.store.findStepUp(session.id);

  return (
    proof !== null && proof.userId === session.userId && proof.expiresAt > runtime.core.clock.now()
  );
}

/**
 * Fresh authentication (read from the live session), plus a recent second-factor proof when the user has a
 * confirmed factor. A user without one passes on fresh authentication alone.
 */
export async function requireStepUp<A>(
  runtime: Runtime,
  session: StoredSession<A>,
): Promise<AuthResult<void>> {
  const live = await runtime.core.requireFreshLiveSession(session);

  if (!live.ok) return live;

  const factor = await runtime.store.findFactor(session.userId);

  if (factor?.confirmed !== true || (await hasStepUp(runtime, session))) return ok();

  return fail('second_factor_required', 'step_up_required');
}

export interface VerifyProofInput {
  readonly userId: string;
  /** The code the user typed, or nothing to ask whether one is needed. */
  readonly proof?: SecondFactorProof;
  /** What the proof is for, in the audit rows (`two_factor.verified` `data.action`). */
  readonly action: string;
  readonly meta: RequestMeta;
}

/**
 * Checks a second factor for a user without a session. Without a proof:
 * `ok({ proved: false })` when the user has no confirmed factor (nothing to
 * prove), `second_factor_required` when it has one. With a proof:
 * `ok({ proved: true })` when it is right, `invalid_second_factor` otherwise,
 * also for a user with no confirmed factor or no user at all (whose codes
 * lock nothing). Every call counts on the per-IP limit. Both answers say
 * whether the account has a factor, and wrong codes lock a real factor:
 * call it only for someone who proved control of the account. It never
 * issues or touches a session.
 */
export async function verifyProof(
  runtime: Runtime,
  input: VerifyProofInput,
): Promise<AuthResult<{ proved: boolean }>> {
  const { core, store } = runtime;
  const { userId, action, meta } = input;
  const limited = await limitIp(runtime, meta);

  if (limited) return limited;

  const factor = await store.findFactor(userId);
  const guarded = factor?.confirmed === true;

  // No audit row here: every call would write one, and the answer is the
  // whole outcome (nothing was tried).
  if (!input.proof)
    return guarded
      ? fail('second_factor_required', `${action}_second_factor_missing`)
      : ok({ proved: false });

  // A user with no confirmed factor can never pass, so a guess for it is
  // counted on a key of its own and names no account: junk codes neither
  // lock the user's real factor key nor climb the permanent lockout tier.
  // The check itself makes the same calls as a wrong code.
  const check = await checkProof(runtime, {
    userId: guarded ? userId : null,
    account: guarded ? factorAccount(userId) : unguardedAccount(userId),
    proof: input.proof,
    blocked: null,
    meta,
  });

  if (!check.ok)
    return refused(
      runtime,
      'two_factor.failed',
      'invalid_second_factor',
      `${action}_second_factor_${check.reason}`,
      userId,
      meta,
    );

  await core.emit(
    { type: 'two_factor.verified', userId, data: { method: check.kind, action } },
    meta,
  );

  return ok({ proved: true });
}

/** Proves the second factor for this session. */
export async function stepUp<A>(
  runtime: Runtime,
  input: { session: StoredSession<A>; proof: SecondFactorProof; meta: RequestMeta },
): Promise<AuthResult<{ expiresAt: number }>> {
  const { session, meta } = input;
  const limited = await limitIp(runtime, meta);

  if (limited) return limited;

  const check = await checkProof(runtime, {
    userId: session.userId,
    account: factorAccount(session.userId),
    proof: input.proof,
    blocked: null,
    meta,
  });

  if (!check.ok)
    return refused(
      runtime,
      'two_factor.failed',
      'invalid_second_factor',
      check.reason,
      session.userId,
      meta,
    );

  const expiresAt = await recordStepUp(runtime, session);

  await runtime.core.emit(
    { type: 'two_factor.step_up', userId: session.userId, data: { method: check.kind } },
    meta,
  );

  return ok({ expiresAt });
}
