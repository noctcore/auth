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
 *
 * Guide: Learn, "Second factors".
 */
import { checkProof, type SecondFactorProof } from './proofs';
import { factorAccount, limitIp, refused, type Runtime } from './runtime';
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
