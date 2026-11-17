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
      readonly reason: 'locked' | 'account_ip_budget' | 'device_budget';
      readonly newLock?: { until: number };
    };

/** A second-factor attempt: let through, or refused (locked now or already). */
export type FactorGate =
  { readonly allowed: true } | { readonly allowed: false; readonly newLock?: { until: number } };

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
