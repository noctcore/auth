/** The throttle's configuration and the answers it gives. */
import { assertCount, configMilliseconds } from '../shared/config-checks';
import type { Duration } from '../shared/duration';
import { AuthConfigError } from '../shared/errors';

export interface RateLimitRule {
  readonly limit: number;
  readonly window: Duration;
}

export interface LockoutOptions {
  /** Attempts per (account, IP) per window. Default 5 per 15 min. */
  readonly perAccountIp?: RateLimitRule;
  /** Attempts per account from all sources per window. Default 10 per 15 min, close to one attempt a minute. */
  readonly perAccount?: RateLimitRule;
  /** First lock duration; each further lock multiplies it by 3. Default 5 min. */
  readonly baseLock?: Duration;
  /** Cap on a single lock. Default 1 h. */
  readonly maxLock?: Duration;
  /** The backoff tier resets after this long without a new lock. Default 24 h. */
  readonly quietPeriod?: Duration;
  /**
   * Attempts per trusted device per window, and also the budget shared by all
   * of an account's devices together. Default 5 per 15 min.
   */
  readonly perDevice?: RateLimitRule;
  /** Oldest device token accepted, checked on use. Default 30 d. */
  readonly deviceMaxAge?: Duration;
  /**
   * Opt in to a permanent tier: an account that keeps getting locked stays
   * locked until an admin clears it (`auth.lockout.clear`). Off by default.
   * The count is of locks in a row, password locks and second-factor locks
   * alike, reset by a completed sign-in (every factor proved, not just the
   * password) or a completed password reset.
   *
   * Trade-off: anyone who knows an address can spread failures over many IPs
   * and lock its owner out for good on purpose (denial of service). Pair it
   * with a captcha on login and per-IP rate limits, and keep `trustedDevices`
   * on unless the lock must hold against the owner too.
   */
  readonly permanent?: PermanentLockOptions;
  /**
   * Answer `account_locked` from login while the account is locked (for a
   * while or for good) instead of `invalid_credentials`. Off by default.
   *
   * Trade-off: the answer tells anyone who tries the address that it is
   * locked and, for a temporary lock, when it lifts. Unknown addresses lock
   * too, so the answer alone does not prove an account, but it confirms the
   * address is under attack and gives an enumeration signal the generic
   * answer does not. Pair it with a captcha and per-IP rate limits.
   */
  readonly revealLocked?: boolean;
}

export interface PermanentLockOptions {
  /**
   * How many temporary locks in a row (each within `quietPeriod` of the last,
   * with no completed sign-in or password reset between; a correct password
   * with a second factor still owed does not count as one) an account may
   * take, password and second-factor locks alike: the next lock is
   * permanent. At least 1.
   */
  readonly afterLocks: number;
  /**
   * Default true: the owner's trusted-device cookie still lets a correct
   * password through a permanent lock, with the same device budgets as under
   * a temporary one, so an attacker can lock out everyone but the owner on a
   * device they signed in from. The lock deletes the account's sessions but
   * keeps the device cookies; sessions from a device sign-in may
   * reauthenticate and change the password, but no session may change the
   * email until an admin clears the lock. Other ways in still mint a session,
   * each needing a correct password or the app's SSO: an app's SSO through
   * `issueSession`, a two-factor challenge started before the lock, and a
   * login racing the revocation.
   *
   * False: the lock holds against every login. It bumps the revocation epoch
   * (ending every session and device cookie), and refuses every session
   * door (issuing a session by any path, validating one, reauthentication,
   * password change, email change, email verification) until an admin
   * clears it.
   */
  readonly trustedDevices?: boolean;
}

/** What a new lock is: until when, and whether it is the permanent tier. */
export interface NewLock {
  /** When the lock ends, in ms since the epoch; for a permanent lock, the far-future expiry it is stored with. */
  readonly until: number;
  readonly permanent?: true;
}

/** Which lock: an address, or an account by its current address. */
export type LockTarget = { readonly email: string } | { readonly userId: string };

/** An account's lock state, as an admin sees it. */
export interface LockState {
  /** True while a temporary or a permanent lock is in force. */
  readonly locked: boolean;
  /** True when the permanent tier holds the account, whatever the temporary lock does. */
  readonly permanent: boolean;
  /** When the temporary lock ends; null when there is none or the lock is permanent. */
  readonly until: Date | null;
}

export interface Hit {
  readonly allowed: boolean;
  readonly count: number;
  readonly retryAfterSeconds: number;
  /** True only on the first refused hit of a window: emit one audit row per window, not one per request. */
  readonly firstRefusal: boolean;
}

export type LoginGate =
  /** `viaDevice`: let through a lock by a device token; report the outcome with `deviceFailed` or `loginSucceeded`. */
  | { readonly allowed: true; readonly viaDevice?: true }
  | {
      readonly allowed: false;
      readonly reason: 'locked' | 'permanently_locked' | 'account_ip_budget' | 'device_budget';
      readonly newLock?: NewLock;
      /**
       * Set (only with `revealLocked`) when the refusal is the account's lock,
       * not one source's budget: `permanent` for the permanent tier, else
       * `until`, when the temporary lock ends.
       */
      readonly lock?: { readonly until: number } | { readonly permanent: true };
    };

/** A second-factor attempt: let through, or refused (locked now or already). */
export type FactorGate =
  { readonly allowed: true } | { readonly allowed: false; readonly newLock?: NewLock };

/** A rule with its window in milliseconds, ready for the counter store. */
export interface WindowRule {
  readonly limit: number;
  readonly windowMs: number;
}

/**
 * The configured rule, or the default for each part the app left out (a
 * rule or a part that is undefined or null). `name` is the option's path,
 * for the error a rule that is not an object or a window that is not a
 * duration throws.
 */
export function windowRule(
  name: string,
  rule: RateLimitRule | null | undefined,
  limit: number,
  window: Duration,
): WindowRule {
  if (rule !== undefined && rule !== null && typeof rule !== 'object')
    throw new AuthConfigError(`${name} must be a { limit, window } rule`);

  return {
    limit: rule?.limit ?? limit,
    windowMs: configMilliseconds(`${name}.window`, rule?.window, window),
  };
}

/**
 * Refuses a rule that would never count or never refuse: a `NaN`, zero,
 * negative or fractional limit, or a zero window (each hit would open a new
 * window, so the count would never pass 1). `name` is the option's path.
 */
export function assertWindowRule(name: string, rule: WindowRule): void {
  assertCount(`${name}.limit`, rule.limit);

  if (rule.windowMs <= 0) throw new AuthConfigError(`${name}.window must be longer than zero`);
}
