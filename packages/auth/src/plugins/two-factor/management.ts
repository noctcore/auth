/**
 * A signed-in user's factor: its status, new recovery codes, turning it off,
 * and forgetting trusted devices.
 *
 * Turning the factor off and new recovery codes are step-up actions: fresh
 * authentication plus a second-factor proof in this session. Neither can be
 * done with the password alone, so a stolen password (or a reset done from a
 * stolen mailbox) cannot be turned into an account without a second factor.
 * A factor the app requires cannot be turned off at all. There is no "I lost
 * everything" path in the library: the recovery codes are the way back, and
 * past them the app's own support process decides.
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
