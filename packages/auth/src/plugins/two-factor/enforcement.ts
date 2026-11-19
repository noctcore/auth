/**
 * Enforcement with a grace period (the `enforcement` option).
 *
 * - The app's policy says, per user, whether a factor is required and until
 *   when a user without one may carry on as usual. The plugin never models
 *   tenants: the app maps the user to whatever its rule hangs on.
 * - It is asked live, on every validated request of a user without a
 *   confirmed factor (`sessionStanding`), so a policy change applies on the
 *   next request. A user with a confirmed factor costs one store read.
 * - In the grace window the session works as usual and carries
 *   `twoFactor: { state: 'grace', graceEndsAt }`. After it the session is
 *   `enrollment-only`: the adapters let it reach only the routes marked for
 *   enrollment (and whatever the app marks with them, sign out included).
 * - A policy that throws is read as required with the grace window over:
 *   fail closed, logged by the error's name only (its message could carry
 *   the user's address).
 * - `sweepUnenrolled` revokes the sessions of required users past their
 *   grace window, for the app's scheduler.
 *
 * Guide: Build, "Two-factor" (enforcement with a grace period).
 */
import type { TwoFactorEnforcement, TwoFactorPolicy } from './options';
import type { Runtime } from './runtime';
import type { SessionStanding, TwoFactorStanding } from '../../core/hooks';
import type { AuthUser, StoredSession } from '../../ports/stores';

/** The revocation reason the sweep reports to `onSessionsRevoked`. */
export const TWO_FACTOR_REQUIRED_REVOCATION = 'two-factor-required';

/** A policy answer, read: whether required, and the grace window's end (null: none or over). */
interface ReadPolicy {
  readonly required: boolean;
  readonly graceEndsAt: number | null;
  /** The policy threw. */
  readonly failed: boolean;
}

const FAILED: ReadPolicy = { required: true, graceEndsAt: null, failed: true };

/** Asks the app's policy; a throw or a malformed answer reads as required with no grace. */
async function readPolicy(
  runtime: Runtime,
  enforcement: TwoFactorEnforcement,
  user: AuthUser,
): Promise<ReadPolicy> {
  let answer: TwoFactorPolicy;

  try {
    answer = await enforcement({ user });
  } catch (error) {
    // The name only: an app's message could quote the user's address.
    runtime.core.logger.error('twoFactor: the enforcement policy threw; read as enrollment-only', {
      error: error instanceof Error ? error.name : typeof error,
    });

    return FAILED;
  }

  if (typeof answer !== 'object' || answer === null) {
    runtime.core.logger.error(
      'twoFactor: the enforcement policy returned no answer; read as enrollment-only',
    );

    return FAILED;
  }

  return {
    required: answer.required !== false,
    graceEndsAt: graceEnd(answer.graceEndsAt),
    failed: false,
  };
}

function graceEnd(value: TwoFactorPolicy['graceEndsAt']): number | null {
  const ms = value instanceof Date ? value.getTime() : value;

  return typeof ms === 'number' && Number.isFinite(ms) ? ms : null;
}

/** Where a required user without a factor stands now, from a read policy. */
function standingFrom(policy: ReadPolicy, now: number): TwoFactorStanding | null {
  if (!policy.required) return null;

  return policy.graceEndsAt !== null && policy.graceEndsAt > now
    ? { state: 'grace', graceEndsAt: policy.graceEndsAt }
    : { state: 'enrollment-only' };
}

/**
 * The standing of a user without a confirmed factor (the caller checked):
 * null when enforcement is off or the policy does not require one.
 */
export async function standingOfUser(
  runtime: Runtime,
  user: AuthUser,
): Promise<TwoFactorStanding | null> {
  const { enforcement } = runtime.settings;

  if (!enforcement) return null;

  return standingFrom(await readPolicy(runtime, enforcement, user), runtime.core.clock.now());
}

/** The `sessionStanding` hook: installed only when `enforcement` is configured. */
export async function sessionStanding(
  runtime: Runtime,
  session: StoredSession<unknown>,
): Promise<SessionStanding | undefined> {
  // The factor first: the steady state (enrolled) stops at one read.
  const factor = await runtime.store.findFactor(session.userId);

  if (factor?.confirmed === true) return undefined;

  // A deleted user: the adapters sign the session out; anything else reading
  // the standing gets the narrowest one.
  const user = await runtime.core.users.findById(session.userId);

  if (!user) return { twoFactor: { state: 'enrollment-only' } };

  const standing = await standingOfUser(runtime, user);

  return standing ? { twoFactor: standing } : undefined;
}

/** Whether a factor is required of this user, under either option; a failed policy reads as required. */
export async function isRequired(runtime: Runtime, user: AuthUser): Promise<boolean> {
  const { enforcement } = runtime.settings;

  if (enforcement) return (await readPolicy(runtime, enforcement, user)).required;

  return runtime.settings.required({ user });
}

export interface SweepInput {
  /**
   * The users to check: the ones your policy may require a factor of (a
   * tenant's members, say). Any iterable or async iterable, so a large set
   * can be paged from your database. Users with a confirmed factor, users
   * still in their grace window and unknown ids are skipped.
   */
  readonly userIds: Iterable<string> | AsyncIterable<string>;
}

export interface SweepResult {
  /** How many ids were checked. */
  readonly checked: number;
  /** The users whose sessions were revoked (only users who had a live session). */
  readonly revoked: readonly string[];
  /** How many users were skipped because the policy threw (logged); retried on the next sweep. */
  readonly failed: number;
}

/**
 * Revokes every session of each required user still without a confirmed
 * factor after their grace window, with reason `two-factor-required` (so
 * `onSessionsRevoked` hears it, with the session handles). Their next sign-in
 * gets an enrollment-only session. A user whose policy throws is skipped,
 * not revoked: validation already confines their sessions to enrollment, and
 * a revocation cannot be undone.
 */
export async function sweepUnenrolled(runtime: Runtime, input: SweepInput): Promise<SweepResult> {
  const { core, store } = runtime;
  const { enforcement } = runtime.settings;
  const revoked: string[] = [];
  let checked = 0;
  let failed = 0;

  if (!enforcement) return { checked, revoked, failed };

  for await (const userId of input.userIds) {
    checked += 1;

    const factor = await store.findFactor(userId);

    if (factor?.confirmed === true) continue;

    const user = await core.users.findById(userId);

    if (!user) continue;

    const policy = await readPolicy(runtime, enforcement, user);

    if (policy.failed) {
      failed += 1;
      continue;
    }

    if (standingFrom(policy, core.clock.now())?.state !== 'enrollment-only') continue;

    // No live session: nothing to end, and no audit row for nothing.
    if ((await core.sessions.listActive(user.id)).length === 0) continue;

    await core.revokeAllSessions(user.id, TWO_FACTOR_REQUIRED_REVOCATION);
    revoked.push(user.id);
  }

  return { checked, revoked, failed };
}
