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
 * - With `enforcementStanding: 'at-issue'` the standing is also decided when
 *   a session is issued, and a session issued unrestricted is stamped
 *   (`twoFactorStanding`) and skips every read. The stamp is a keyed hash of
 *   the user, the version, the revocation epoch read before the answer and
 *   the issue time, so only this server can make one, and only a stamp of
 *   the current version, for the session's own user and epoch, younger than
 *   `maxAge`, skips. Whatever could restrict a stamped session ends it
 *   instead: `refreshStanding` (the app's policy change) and `reset` (the
 *   factor gone) revoke the user's sessions whenever `enforcement` is on, in
 *   either mode, so a stamp from an earlier spell under `'at-issue'` cannot
 *   come back. A sign-in that read the old answer and mints after such a
 *   revocation gets a stamp of the old epoch (read live) or loses the core's
 *   epoch fence. A stamp another hook put on a new session is refused
 *   (`stampIsOurs`). Enrolling or a lifted policy only ever frees a session,
 *   and unstamped sessions are read live.
 *
 * Guide: Build, "Two-factor" (enforcement with a grace period).
 */
import type { TwoFactorEnforcement, TwoFactorPolicy } from './options';
import type { Runtime } from './runtime';
import type { SessionStanding, TwoFactorStanding } from '../../core/hooks';
import type { AuthUser, StoredSession } from '../../ports/stores';
import { hexDigestsEqual } from '../../crypto/hash';
import { ok, type AuthResult } from '../../shared/errors';

/** The session attribute that carries the `'at-issue'` stamp. */
export const STANDING_ATTRIBUTE = 'twoFactorStanding';

/** The revocation reason of `refreshStanding`. */
export const TWO_FACTOR_STANDING_REVOCATION = 'two-factor-standing';

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

/** What the policy says of a user without a confirmed factor: `required`, and the standing it implies. */
export interface Assessment {
  readonly required: boolean;
  readonly standing: TwoFactorStanding | null;
}

/**
 * Asks the policy once and derives both answers from it, so a custom
 * `enforcement` function (often a database read) runs one time per call and
 * `required` and `standing` cannot disagree. Without `enforcement`, the
 * `required` option answers and there is no standing.
 */
export async function assessUser(runtime: Runtime, user: AuthUser): Promise<Assessment> {
  const { enforcement } = runtime.settings;

  if (!enforcement) return { required: await runtime.settings.required({ user }), standing: null };

  const policy = await readPolicy(runtime, enforcement, user);

  return { required: policy.required, standing: standingFrom(policy, runtime.core.clock.now()) };
}

/** The key purpose of the stamp's keyed hash. */
const STANDING_PURPOSE = 'two-factor-standing';

/** A stamp as stored: the issue time, a dot, and the keyed hash. */
const STAMP_SHAPE = /^(\d{1,16})\.([0-9a-f]{64})$/u;

type StandingSettings = NonNullable<Runtime['settings']['standing']>;

/** What the stamp's keyed hash covers: an unrestricted issue of this user, version, epoch and time. */
const stampMessage = (userId: string, version: string, epoch: number, issuedAt: number): string =>
  `unrestricted:${userId}:${version}:${epoch}:${issuedAt}`;

/**
 * Whether the session carries a stamp of the current version, issued for its
 * own user at its own epoch, less than `maxAge` ago, and keyed by this
 * server's secret (any key of a rotation). Anything else, a stamp an app hook
 * or a legacy store copied in included, is read live.
 */
function stampedUnrestricted(runtime: Runtime, session: StoredSession<unknown>): boolean {
  const { standing } = runtime.settings;
  const attributes = session.attributes;

  if (standing === null || typeof attributes !== 'object' || attributes === null) return false;

  const value = (attributes as Record<string, unknown>)[STANDING_ATTRIBUTE];
  const parts = typeof value === 'string' ? STAMP_SHAPE.exec(value) : null;

  if (!parts) return false;

  const issuedAt = Number(parts[1]);
  const now = runtime.core.clock.now();

  if (!(issuedAt <= now && now - issuedAt < standing.maxAgeMs)) return false;

  const message = stampMessage(session.userId, standing.version, session.epoch, issuedAt);

  return runtime.core
    .keyedHashes(STANDING_PURPOSE, message)
    .some((expected) => hexDigestsEqual(expected, String(parts[2])));
}

/**
 * The stamp each issue computed, by the user object the core hands to both
 * hooks of one issue, so `beforeSessionCreate` can refuse a session whose
 * attribute some other hook replaced.
 */
const computedStamps = new WeakMap<AuthUser, string | undefined>();

/**
 * The `sessionAttributes` hook under `'at-issue'`: the stamp when the user
 * signs in unrestricted (a confirmed factor, or no factor required), and
 * nothing otherwise. It always sets the attribute, so a stamp a re-issue
 * inherits never outlives a change of answer.
 */
export async function standingAtIssue(
  runtime: Runtime,
  user: AuthUser,
  standing: StandingSettings,
): Promise<Record<string, string | undefined>> {
  // The epoch first: an answer read after it cannot predate a revocation
  // that a session minted at this epoch would survive.
  const epoch = await runtime.core.sessions.readEpoch(user.id);
  const unrestricted = await issuedUnrestricted(runtime, user);
  const issuedAt = runtime.core.clock.now();

  const stamp = unrestricted
    ? `${issuedAt}.${runtime.core.keyedHash(STANDING_PURPOSE, stampMessage(user.id, standing.version, epoch, issuedAt))}`
    : undefined;

  computedStamps.set(user, stamp);

  return { [STANDING_ATTRIBUTE]: stamp };
}

async function issuedUnrestricted(runtime: Runtime, user: AuthUser): Promise<boolean> {
  if ((await runtime.store.findFactor(user.id))?.confirmed === true) return true;

  return (await assessUser(runtime, user)).standing === null;
}

/**
 * The `beforeSessionCreate` check under `'at-issue'`: the session's
 * `twoFactorStanding` is the plugin's own, or absent (a schema that drops
 * it only costs reads). A value another hook put there is refused, so no
 * hook of the app's (one that spreads `inherited`, say) can carry a stamp
 * past the plugin's answer.
 */
export function stampIsOurs(user: AuthUser, attributes: unknown): boolean {
  const value =
    typeof attributes === 'object' && attributes !== null
      ? (attributes as Record<string, unknown>)[STANDING_ATTRIBUTE]
      : undefined;

  return value === undefined || value === computedStamps.get(user);
}

/**
 * Ends every session of the user, so their next sign-in is stamped from the
 * policy's answer now; call it after requiring a factor of the user or
 * changing their policy. It revokes under `'live'` too: a stamp issued during
 * an earlier spell under `'at-issue'` (a rollback, a rolling deploy) would
 * otherwise count again when the option comes back. A no-op
 * (`revoked: false`) only without `enforcement`.
 */
export async function refreshStanding(
  runtime: Runtime,
  input: { readonly userId: string },
): Promise<AuthResult<{ revoked: boolean }>> {
  if (runtime.settings.enforcement === null) return ok({ revoked: false });

  await runtime.core.revokeAllSessions(input.userId, TWO_FACTOR_STANDING_REVOCATION);

  return ok({ revoked: true });
}

/** The `sessionStanding` hook: installed only when `enforcement` is configured. */
export async function sessionStanding(
  runtime: Runtime,
  session: StoredSession<unknown>,
): Promise<SessionStanding | undefined> {
  // Stamped unrestricted at issue, and nothing has ended it since: no read.
  if (stampedUnrestricted(runtime, session)) return undefined;

  // The factor first: the steady state (enrolled) stops at one read.
  const factor = await runtime.store.findFactor(session.userId);

  if (factor?.confirmed === true) return undefined;

  // A deleted user: the adapters sign the session out; anything else reading
  // the standing gets the narrowest one.
  const user = await runtime.core.users.findById(session.userId);

  if (!user) return { twoFactor: { state: 'enrollment-only' } };

  const { standing } = await assessUser(runtime, user);

  return standing ? { twoFactor: standing } : undefined;
}

/** Whether a factor is required of this user, under either option; a failed policy reads as required. */
export async function isRequired(runtime: Runtime, user: AuthUser): Promise<boolean> {
  return (await assessUser(runtime, user)).required;
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
  const { core } = runtime;
  const { enforcement } = runtime.settings;
  const revoked: string[] = [];
  let checked = 0;
  let failed = 0;

  if (!enforcement) return { checked, revoked, failed };

  for await (const userId of input.userIds) {
    checked += 1;

    const first = await pastGrace(runtime, enforcement, userId);

    if (first.failed) failed += 1;

    if (first.user === null) continue;

    // No live session: nothing to end, and no audit row for nothing.
    if ((await core.sessions.listActive(userId)).length === 0) continue;

    // A revocation cannot be undone, and the reads above took time: a user who
    // enrolled, or whose rule changed, since then keeps their sessions.
    const again = await pastGrace(runtime, enforcement, userId);

    if (again.user === null) continue;

    await core.revokeAllSessions(again.user.id, TWO_FACTOR_REQUIRED_REVOCATION);
    revoked.push(again.user.id);
  }

  return { checked, revoked, failed };
}

/**
 * Reads the factor, the user and the policy now: the user when they are
 * required, without a confirmed factor and past their grace window; null
 * otherwise (`failed` when the policy threw, which is never a reason to revoke).
 */
async function pastGrace(
  runtime: Runtime,
  enforcement: TwoFactorEnforcement,
  userId: string,
): Promise<{ readonly user: AuthUser | null; readonly failed: boolean }> {
  const none = { user: null, failed: false };

  if ((await runtime.store.findFactor(userId))?.confirmed === true) return none;

  const user = await runtime.core.users.findById(userId);

  if (!user) return none;

  const policy = await readPolicy(runtime, enforcement, user);

  if (policy.failed) return { user: null, failed: true };

  const standing = standingFrom(policy, runtime.core.clock.now());

  return standing?.state === 'enrollment-only' ? { user, failed: false } : none;
}
