/**
 * The two-factor plugin's options, with the default and the reason for each,
 * checked once when the plugin is created. Where published guidance disagrees
 * on a default, the stricter value wins.
 */
import type { AuthUser } from '../../ports/stores';
import type { SecretCipher, TwoFactorStore } from '../../ports/two-factor';
import { toMilliseconds, type Duration } from '../../shared/duration';
import { AuthConfigError } from '../../shared/errors';

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
}

export interface TwoFactorSettings {
  readonly issuer: string;
  readonly required: (context: { readonly user: AuthUser }) => boolean | Promise<boolean>;
  readonly stepUpWindowMs: number;
  readonly trustedDevices: { readonly ttlMs: number; readonly maxPerUser: number } | null;
  readonly attempts: AttemptRule;
  readonly perIp: AttemptRule;
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

  const stepUpWindowMs = toMilliseconds(options.stepUpWindow ?? '10m');

  if (stepUpWindowMs <= 0) throw new AuthConfigError('twoFactor: stepUpWindow must be positive');

  return {
    issuer: options.issuer,
    required: options.required ?? never,
    stepUpWindowMs,
    trustedDevices: resolveTrustedDevices(options.trustedDevices),
    attempts: resolveRule('attempts', options.attempts ?? { limit: 5, window: '15m' }),
    perIp: resolveRule('perIp', options.perIp ?? { limit: 10, window: '1m' }),
  };
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
