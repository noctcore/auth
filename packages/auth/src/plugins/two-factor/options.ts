/**
 * The two-factor plugin's options, with the default and the reason for each,
 * checked once when the plugin is created. Where published guidance disagrees
 * on a default, the stricter value wins.
 */
import type { AuthUser } from '../../ports/stores';
import type { SecretCipher, TwoFactorStore } from '../../ports/two-factor';
import { toMilliseconds, type Duration } from '../../shared/duration';
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
   * It should not throw: a throw is logged (the error's name only) and read
   * as no match, so the proof is refused like a wrong code.
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
  /** How long a second-factor proof counts for sensitive actions, per session. Default 10 min. */
  readonly stepUpWindow?: Duration;
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
   * new codes once the session is issued, which
   * the challenge returns. Default: none accepted.
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
  readonly stepUpWindowMs: number;
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
/** How long an enrollment waits for its confirmation code. */
export const ENROLLMENT_TTL_MS = 10 * 60_000;

const never = (): boolean => false;

export function resolveSettings(options: TwoFactorOptions): TwoFactorSettings {
  if (!options.store) throw new AuthConfigError('twoFactor: store is required');
  if (!options.cipher) throw new AuthConfigError('twoFactor: cipher is required');

  if (typeof options.issuer !== 'string' || options.issuer.length === 0)
    throw new AuthConfigError('twoFactor: issuer is required');

  // The Key URI Format separates issuer and account with a colon in the label.
  if (options.issuer.includes(':'))
    throw new AuthConfigError('twoFactor: issuer may not contain a colon');

  if (options.enforcement !== undefined && typeof options.enforcement !== 'function')
    throw new AuthConfigError('twoFactor: enforcement must be a function');

  // Two answers to "is a factor required" would disagree sooner or later.
  if (options.enforcement !== undefined && options.required !== undefined)
    throw new AuthConfigError('twoFactor: pass either required or enforcement, not both');

  const stepUpWindowMs = toMilliseconds(options.stepUpWindow ?? '10m');

  if (stepUpWindowMs <= 0) throw new AuthConfigError('twoFactor: stepUpWindow must be positive');

  return {
    issuer: options.issuer,
    required: options.required ?? never,
    enforcement: options.enforcement ?? null,
    stepUpWindowMs,
    trustedDevices: resolveTrustedDevices(options.trustedDevices),
    attempts: resolveRule('attempts', options.attempts ?? { limit: 5, window: '15m' }),
    perIp: resolveRule('perIp', options.perIp ?? { limit: 10, window: '1m' }),
    importedRecoveryCodes: resolveImported(options.importedRecoveryCodes),
  };
}

function resolveImported(
  option: TwoFactorOptions['importedRecoveryCodes'],
): ImportedRecoveryCodes | null {
  if (option === undefined) return null;

  if (typeof option?.hash !== 'function')
    throw new AuthConfigError('twoFactor: importedRecoveryCodes.hash must be a function');

  return option;
}

/** A limit that is a positive integer over a positive window; anything else would never count or never refuse. */
function resolveRule(name: string, rule: AttemptRule): AttemptRule {
  if (!Number.isInteger(rule.limit) || rule.limit < 1)
    throw new AuthConfigError(`twoFactor: ${name}.limit must be a positive integer`);

  if (toMilliseconds(rule.window) <= 0)
    throw new AuthConfigError(`twoFactor: ${name}.window must be positive`);

  return rule;
}

function resolveTrustedDevices(
  option: TwoFactorOptions['trustedDevices'],
): TwoFactorSettings['trustedDevices'] {
  if (option === false) return null;

  const ttlMs = toMilliseconds(option?.ttl ?? '30d');
  const maxPerUser = option?.maxPerUser ?? 5;

  if (ttlMs <= 0) throw new AuthConfigError('twoFactor: trustedDevices.ttl must be positive');

  if (!Number.isInteger(maxPerUser) || maxPerUser < 1)
    throw new AuthConfigError('twoFactor: trustedDevices.maxPerUser must be a positive integer');

  return { ttlMs, maxPerUser };
}
