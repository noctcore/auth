/** The throttle's configuration and the answers it gives. */
import { toMilliseconds, type Duration } from '../shared/duration';

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
   * How many temporary locks in a row (each within `quietPeriod` of the last)
   * an account may take: the next lock is permanent. At least 1.
   */
  readonly afterLocks: number;
  /**
   * Whether the owner's trusted-device cookie still lets a correct password
   * through a permanent lock, with the same device budgets as under a
   * temporary one. Default true: an attacker can then lock out everyone but
   * the owner on a device they signed in from. False makes the lock hold
   * against every login until an admin clears it.
   */
  readonly trustedDevices?: boolean;
}

/** What a new lock is: until when, and whether it is the permanent tier. */
export interface NewLock {
  /** When the lock ends, in ms since the epoch; for a permanent lock, the far-future expiry it is stored with. */
  readonly until: number;
  readonly permanent?: true;
}

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
       * Set when the refusal is the account's lock, not one source's budget:
       * `permanent` for the permanent tier, else `until` when the lock ends
       * (when known).
       */
      readonly lock?: { readonly until?: number; readonly permanent?: true };
    };

/** A second-factor attempt: let through, or refused (locked now or already). */
export type FactorGate =
  { readonly allowed: true } | { readonly allowed: false; readonly newLock?: NewLock };

/** A rule with its window in milliseconds, ready for the counter store. */
export interface WindowRule {
  readonly limit: number;
  readonly windowMs: number;
}

/** The configured rule, or the default for each part the app left out. */
export function windowRule(
  rule: RateLimitRule | undefined,
  limit: number,
  window: Duration,
): WindowRule {
  return { limit: rule?.limit ?? limit, windowMs: toMilliseconds(rule?.window ?? window) };
}
