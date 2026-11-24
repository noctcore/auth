/**
 * A signed-in user's factor: its status, new recovery codes, turning it off,
 * and forgetting trusted devices.
 *
 * Turning the factor off and new recovery codes are step-up actions: fresh
 * authentication plus a second-factor proof in this session. Neither can be
 * done with the password alone, so a stolen password (or a reset done from a
 * stolen mailbox) cannot be turned into an account without a second factor.
 * A factor the app requires cannot be turned off at all. There is no "I lost
 * everything" path for the user: the recovery codes are the way back, and
 * past them the app's own support process decides, and ends with `reset`, an
 * admin action that never runs on the user's word alone: your code calls it
 * after its own checks. It is audited and mailed like a disable.
 *
 * Guide: Learn, "Second factors"; Build, "Two-factor".
 */
import { assessUser, isRequired } from './enforcement';
import { issueRecoveryCodes } from './proofs';
import { refused, type Runtime } from './runtime';
import { requireStepUp } from './step-up';
import type { TwoFactorStanding } from '../../core/hooks';
import { mailMeta } from '../../ports/mail';
import type { StoredSession } from '../../ports/stores';
import { fail, ok, type AuthResult } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

/** The revocation reason of a reset under `enforcementStanding: 'at-issue'`. */
export const TWO_FACTOR_RESET_REVOCATION = 'two-factor-reset';

export interface TwoFactorStatus {
  /** A confirmed factor guards this user's logins. */
  readonly enabled: boolean;
  /** An enrollment waits for its confirmation code. */
  readonly pending: boolean;
  /** The app requires a factor of this user. */
  readonly required: boolean;
  /**
   * With `enforcement`: the user's standing now (grace with its end, or
   * enrollment-only), as validation computes it. Null when enforcement is
   * off, the factor is on, or none is required.
   */
  readonly enforcement: TwoFactorStanding | null;
  readonly recoveryCodesRemaining: number;
}

export async function status<A>(
  runtime: Runtime,
  session: StoredSession<A>,
): Promise<AuthResult<TwoFactorStatus>> {
  const user = await runtime.core.users.findById(session.userId);

  if (!user) return fail('session_expired', 'user_missing');

  const factor = await runtime.store.findFactor(user.id);
  const enabled = factor?.confirmed === true;
  // One answer from the policy, so `required` and `enforcement` agree.
  const { required, standing } = await assessUser(runtime, user);

  return ok({
    enabled,
    pending: factor?.confirmed === false,
    required,
    enforcement: enabled ? null : standing,
    recoveryCodesRemaining: enabled ? await runtime.store.countRecoveryCodes(user.id) : 0,
  });
}

/**
 * Turns the factor off (or drops a pending enrollment): needs a step-up, and is
 * refused for a user the app requires a factor of. Deletes the factor, the
 * recovery codes and every trusted device, and mails the owner.
 */
export async function disable<A>(
  runtime: Runtime,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<AuthResult<{ disabled: boolean }>> {
  const { core, store } = runtime;
  const { session, meta } = input;
  const user = await core.users.findById(session.userId);

  if (!user) return fail('session_expired', 'user_missing');

  const factor = await store.findFactor(user.id);

  if (!factor) return ok({ disabled: false });

  if (factor.confirmed && (await isRequired(runtime, user)))
    return refused(runtime, 'two_factor.refused', 'forbidden', 'factor_required', user.id, meta);

  const allowed = await requireStepUp(runtime, session);

  if (!allowed.ok)
    return refused(runtime, 'two_factor.refused', allowed.code, allowed.reason, user.id, meta);

  await store.deleteFactor(user.id);
  await store.replaceRecoveryCodes(user.id, []);
  await store.deleteTrustedDevices(user.id);

  if (!factor.confirmed) return ok({ disabled: false });

  await core.emit({ type: 'two_factor.disabled', userId: user.id }, meta);

  core.mail({
    type: 'two-factor-disabled',
    to: user.email,
    userId: user.id,
    at: new Date(core.clock.now()),
    ...mailMeta(meta),
  });

  return ok({ disabled: true });
}

/**
 * An admin's reset of another user's factor (pending or confirmed): deletes
 * it, the recovery codes and every trusted device, so the next login gets no
 * challenge (or an enrollment one, when a factor is required). The user's
 * step-up proofs end with their sessions; revoke those
 * (`context.revokeAllSessions`) if the reset is for a takeover. Every reset
 * is audited (`two_factor.reset`, `data.actor` when named); a confirmed
 * factor's owner is mailed (`two-factor-disabled` with `reset: true`).
 */
export async function reset(
  runtime: Runtime,
  input: { userId: string; actor?: string; meta: RequestMeta },
): Promise<AuthResult<{ reset: boolean }>> {
  const { core, store } = runtime;
  const { userId, meta } = input;
  const factor = await store.findFactor(userId);

  if (!factor) return ok({ reset: false });

  await store.deleteFactor(userId);
  await store.replaceRecoveryCodes(userId, []);
  await store.deleteTrustedDevices(userId);

  // Under `'at-issue'` a session stamped for the factor would skip the
  // standing the user now has: end it (enforcement.ts).
  if (factor.confirmed && runtime.settings.standingStamp !== null)
    await core.revokeAllSessions(userId, TWO_FACTOR_RESET_REVOCATION);

  await core.emit(
    {
      type: 'two_factor.reset',
      userId,
      data: { confirmed: factor.confirmed, ...(input.actor ? { actor: input.actor } : {}) },
    },
    meta,
  );

  const user = factor.confirmed ? await core.users.findById(userId) : null;

  if (user)
    core.mail({
      type: 'two-factor-disabled',
      to: user.email,
      userId,
      at: new Date(core.clock.now()),
      reset: true,
      ...mailMeta(meta),
    });

  return ok({ reset: true });
}

/** A new set of recovery codes (every old one dies): needs a step-up. Show them once. */
export async function regenerateRecoveryCodes<A>(
  runtime: Runtime,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<AuthResult<{ recoveryCodes: string[] }>> {
  const { session, meta } = input;
  const factor = await runtime.store.findFactor(session.userId);

  if (factor?.confirmed !== true)
    return refused(runtime, 'two_factor.refused', 'forbidden', 'no_factor', session.userId, meta);

  const allowed = await requireStepUp(runtime, session);

  if (!allowed.ok)
    return refused(
      runtime,
      'two_factor.refused',
      allowed.code,
      allowed.reason,
      session.userId,
      meta,
    );

  return ok({ recoveryCodes: await issueRecoveryCodes(runtime, session.userId, meta) });
}

/** Forgets every trusted device of the user: each one faces the challenge again. */
export async function revokeTrustedDevices<A>(
  runtime: Runtime,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<AuthResult<void>> {
  await runtime.store.deleteTrustedDevices(input.session.userId);

  await runtime.core.emit(
    { type: 'two_factor.trusted_devices_revoked', userId: input.session.userId },
    input.meta,
  );

  return ok();
}
