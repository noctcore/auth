/**
 * The two-factor plugin's options, with the default and the reason for each,
 * checked once when the plugin is created. Where published guidance disagrees
 * on a default, the stricter value wins.
 */
import type { AuthUser } from '../../ports/stores';
import type { SecretCipher, TwoFactorStore } from '../../ports/two-factor';
import { assertFunction, configMilliseconds } from '../../shared/config-checks';
import type { Duration } from '../../shared/duration';
import { AuthConfigError } from '../../shared/errors';

/**
 * Recovery codes carried over from the app's earlier scheme. The migration
 * script stores their hashes with `importedRecoveryCodeHashes`; this option
 * tells the plugin how a typed code is hashed under that scheme.
 */
export interface ImportedRecoveryCodes {
  /**
   * The old scheme's hash of a typed code, as the migration stored it (for
   * example the hex SHA-256 of the code with dashes removed and letters upper
   * cased), or null when the input cannot be one of its codes. Must be
   * deterministic: a per-code salted hash (bcrypt, Argon2) cannot be looked
   * up, so those users re-enroll instead. `userId` is there for a scheme
   * that salted per user. The input is a string of at most 64 characters.
   *
   * It runs on every recovery-code proof, also when the check is already
   * going to refuse (a blocked or locked challenge, an unknown user), so the
   * work is the same; there `userId` is `NO_SUCH_USER_ID`, an id no store
   * issues. Do not assume the user exists, and do not look anything up that
   * fails for an unknown id.
   *
   * It should not throw: a throw is logged (the error's name only) and read
   * as no match, so the proof is refused like a wrong code. The public answer
   * is the same either way, but the audit reason differs: when the input is
   * not in the plugin's own code format either, the refusal is recorded as
   * `malformed_recovery_code`, not `wrong_recovery_code`.
   */
  readonly hash: (
    code: string,
    context: { readonly userId: string },
  ) => string | null | Promise<string | null>;
}

/** A fixed window: at most `limit` hits per `window`. */
export interface AttemptRule {
  readonly limit: number;
  readonly window: Duration;
}

export interface TwoFactorOptions {
  /** Factors, recovery codes, trusted devices and step-up proofs. `@noctcore/auth-prisma` and `@noctcore/auth-redis` ship one. */
  readonly store: TwoFactorStore;
  /** Encrypts TOTP secrets at rest. The app owns the key; see `SecretCipher`. */
  readonly cipher: SecretCipher;
  /** The name the authenticator app shows above the code. No colon. */
  readonly issuer: string;
  /**
   * Whether this user must have a second factor (per user, per tenant, per
   * role: the app decides). A required user without one gets an enrollment
   * challenge at login instead of a session, and cannot turn the factor off.
   * Default: never required.
   */
  readonly required?: (context: { readonly user: AuthUser }) => boolean | Promise<boolean>;
  /**
   * Enforcement with a grace period, checked live on every request: the
   * app's policy for this user (look the user's tenant, role or plan up in
   * here; the plugin never models tenants). While a factor is required and
   * none is set up, sign-in works as usual and every validated session
   * carries `twoFactor: { state: 'grace', graceEndsAt }` until the grace
   * window ends; after that the session is `enrollment-only`, and the
   * adapters let it reach only the routes marked for enrollment. A policy
   * change takes effect on the next request, without a new sign-in.
   *
   * Runs on every validated request of a user without a confirmed factor
   * (users with one stop at one store read), so keep it cheap: cache tenant
   * policies in the app, and expect a change to apply once that cache does.
   * A policy that throws is read as required with the grace window over
   * (fail closed), logged by the error's name only.
   *
   * Replaces `required`: pass one or the other. Default: off.
   */
  readonly enforcement?: TwoFactorEnforcement;
  /**
   * When `enforcement` decides a session's standing. `'live'` (default):
   * on every validated request, as above. `'at-issue'`: also when the
   * session is issued, and a session issued unrestricted (a confirmed
   * factor, or no factor required) is stamped so (the `twoFactorStanding`
   * session attribute) and validates without any read; every other session
   * is read live, so enrolling or the policy lifting still frees it on the
   * next request. Nothing the plugin cannot see can reach a stamped session,
   * so after you require a factor of a user (or change their policy), call
   * `twoFactor.refreshStanding({ userId })`: it ends the user's sessions,
   * and their next sign-in is stamped from the new answer. For a change to
   * many users at once, pass `{ mode: 'at-issue', version }` with a new
   * `version`: sessions stamped under another version are read live again.
   * With a session attribute schema, let `twoFactorStanding` through (a
   * schema that drops it only costs the reads; one that refuses unknown keys
   * refuses every sign-in). Needs `enforcement`.
   */
  readonly enforcementStanding?:
    'live' | 'at-issue' | { readonly mode: 'at-issue'; readonly version: string };
  /** How long a second-factor proof counts for sensitive actions, per session. Default 10 min. */
  readonly stepUpWindow?: Duration;
  /**
   * How long a pending secret from `enroll` accepts its confirmation code
   * (`Enrollment.expiresAt`). Positive, at most 24 h. Default 10 min. It also
   * dates when a factor counts as set up for an app's own re-issue of a
   * session (a session created after the window closed passes), so shrinking
   * it while enrollments are pending lets a session created between the new
   * and the old end pass; turn factors on with `revokeOtherSessions: true`.
   */
  readonly enrollmentWindow?: Duration;
  /**
   * "Remember this device": a device that passed the challenge skips it on
   * later logins (never the password, never a step-up). Default 30 days, 5
   * devices per user. `false` turns it off.
   */
  readonly trustedDevices?: { readonly ttl?: Duration; readonly maxPerUser?: number } | false;
  /**
   * Wrong codes per account, from every IP, before the factor locks with the
   * password lockout's capped backoff. Default 5 per 15 min.
   */
  readonly attempts?: AttemptRule;
  /** Code checks per client IP. Default 10 per minute. */
  readonly perIp?: AttemptRule;
  /**
   * Accept recovery codes imported from the app's earlier scheme, each once.
   * Passing the login challenge with one replaces the user's whole set with
   * new codes once the session is issued, which the challenge returns; the
   * mail and the audit row then count the new set. Of two logins racing with
   * two imported codes only one replaces the set and shows it; the other
   * gets its session with `recoveryCodes: null`. A failed replacement also
   * keeps the session and returns null (logged). Default: none accepted.
   */
  readonly importedRecoveryCodes?: ImportedRecoveryCodes;
}

/** What the app's enforcement policy answers for one user. */
export interface TwoFactorPolicy {
  /** This user must set up a second factor. */
  readonly required: boolean;
  /**
   * Until when a required user without a factor may still use the app as
   * usual. Absent, null or already past: the grace window is over.
   */
  readonly graceEndsAt?: Date | number | null;
}

/** The app's enforcement policy, asked per user. */
export type TwoFactorEnforcement = (context: {
  readonly user: AuthUser;
}) => TwoFactorPolicy | Promise<TwoFactorPolicy>;

export interface TwoFactorSettings {
  readonly issuer: string;
  readonly required: (context: { readonly user: AuthUser }) => boolean | Promise<boolean>;
  /** The enforcement policy, or null when `enforcement` is not configured. */
  readonly enforcement: TwoFactorEnforcement | null;
  /** The stamp of a session issued unrestricted under `'at-issue'`; null when the standing is read live. */
  readonly standingStamp: string | null;
  readonly stepUpWindowMs: number;
  readonly enrollmentWindowMs: number;
  readonly trustedDevices: { readonly ttlMs: number; readonly maxPerUser: number } | null;
  readonly attempts: AttemptRule;
  readonly perIp: AttemptRule;
  readonly importedRecoveryCodes: ImportedRecoveryCodes | null;
}

/** The token purpose of a login challenge: never a session, a reset link or a reset ticket. */
export const CHALLENGE_PURPOSE = 'two-factor-challenge';
/** Lifetime of a login challenge: long enough to open the app and type a code. */
export const CHALLENGE_TTL_MS = 5 * 60_000;
/** Codes one challenge accepts before it is spent. */
export const CHALLENGE_MAX_ATTEMPTS = 5;
/** The longest `enrollmentWindow`: a pending secret is a half-finished setup, not a standing one. */
export const MAX_ENROLLMENT_WINDOW_MS = 24 * 3600_000;

const never = (): boolean => false;

/** Neither undefined nor null: null is an option left out, as everywhere else. */
const isSet = <T>(value: T): value is NonNullable<T> => value !== undefined && value !== null;

export function resolveSettings(options: TwoFactorOptions): TwoFactorSettings {
  if (!options.store) throw new AuthConfigError('twoFactor: store is required');
  if (!options.cipher) throw new AuthConfigError('twoFactor: cipher is required');

  if (typeof options.issuer !== 'string' || options.issuer.length === 0)
    throw new AuthConfigError('twoFactor: issuer is required');

  // The Key URI Format separates issuer and account with a colon in the label.
  if (options.issuer.includes(':'))
    throw new AuthConfigError('twoFactor: issuer may not contain a colon');

  assertFunction('twoFactor: enforcement', options.enforcement);
  assertFunction('twoFactor: required', options.required);

  // Two answers to "is a factor required" would disagree sooner or later.
  if (isSet(options.enforcement) && isSet(options.required))
    throw new AuthConfigError('twoFactor: pass either required or enforcement, not both');

  const stepUpWindowMs = configMilliseconds('twoFactor: stepUpWindow', options.stepUpWindow, '10m');

  if (stepUpWindowMs <= 0) throw new AuthConfigError('twoFactor: stepUpWindow must be positive');

  const enrollmentWindowMs = configMilliseconds(
    'twoFactor: enrollmentWindow',
    options.enrollmentWindow,
    '10m',
  );

  if (enrollmentWindowMs <= 0 || enrollmentWindowMs > MAX_ENROLLMENT_WINDOW_MS)
    throw new AuthConfigError('twoFactor: enrollmentWindow must be positive and at most 24 hours');

  return {
    issuer: options.issuer,
    required: options.required ?? never,
    enforcement: options.enforcement ?? null,
    standingStamp: resolveStandingStamp(options),
    stepUpWindowMs,
    enrollmentWindowMs,
    trustedDevices: resolveTrustedDevices(options.trustedDevices),
    attempts: resolveRule('attempts', options.attempts ?? { limit: 5, window: '15m' }),
    perIp: resolveRule('perIp', options.perIp ?? { limit: 10, window: '1m' }),
    importedRecoveryCodes: resolveImported(options.importedRecoveryCodes),
  };
}

/** The default `version` of `'at-issue'`. */
const FIRST_STANDING_VERSION = '1';

function resolveStandingStamp(options: TwoFactorOptions): string | null {
  const option = options.enforcementStanding;

  if (!isSet(option) || option === 'live') return null;

  let version: string;

  if (option === 'at-issue') version = FIRST_STANDING_VERSION;
  else if (
    typeof option === 'object' &&
    (option as { mode?: unknown }).mode === 'at-issue' &&
    typeof option.version === 'string' &&
    option.version.length > 0
  )
    version = option.version;
  else
    throw new AuthConfigError(
      "twoFactor: enforcementStanding must be 'live', 'at-issue' or { mode: 'at-issue', version }",
    );

  if (!isSet(options.enforcement))
    throw new AuthConfigError('twoFactor: enforcementStanding needs enforcement');

  return `unrestricted:${version}`;
}

function resolveImported(
  option: TwoFactorOptions['importedRecoveryCodes'],
): ImportedRecoveryCodes | null {
  if (!isSet(option)) return null;

  if (typeof option.hash !== 'function')
    throw new AuthConfigError('twoFactor: importedRecoveryCodes.hash must be a function');

  return option;
}

/** A limit that is a positive integer over a positive window; anything else would never count or never refuse. */
function resolveRule(name: string, rule: AttemptRule): AttemptRule {
  if (!Number.isInteger(rule.limit) || rule.limit < 1)
    throw new AuthConfigError(`twoFactor: ${name}.limit must be a positive integer`);

  if (configMilliseconds(`twoFactor: ${name}.window`, rule.window, 0) <= 0)
    throw new AuthConfigError(`twoFactor: ${name}.window must be positive`);

  return rule;
}

function resolveTrustedDevices(
  option: TwoFactorOptions['trustedDevices'],
): TwoFactorSettings['trustedDevices'] {
  if (option === false) return null;

  // `true` or a string such as "false" from an env file would read as on with the defaults.
  if (option !== undefined && option !== null && typeof option !== 'object')
    throw new AuthConfigError('twoFactor: trustedDevices must be false or an object');

  const ttlMs = configMilliseconds('twoFactor: trustedDevices.ttl', option?.ttl, '30d');
  const maxPerUser = option?.maxPerUser ?? 5;

  if (ttlMs <= 0) throw new AuthConfigError('twoFactor: trustedDevices.ttl must be positive');

  if (!Number.isInteger(maxPerUser) || maxPerUser < 1)
    throw new AuthConfigError('twoFactor: trustedDevices.maxPerUser must be a positive integer');

  return { ttlMs, maxPerUser };
}
