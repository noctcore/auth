/**
 * Throttling: per-door rate limits and the login lockout policy, as decisions
 * over a CounterStore.
 *
 * Rate limits are fixed windows that FAIL CLOSED: a counter store that cannot
 * answer throws, and the flow refuses rather than letting the request through
 * uncounted.
 *
 * The lockout policy is built so that knowing someone's email is not enough to
 * lock them out for long, and so that a locked account looks exactly like a
 * wrong password:
 *
 * - Attempts are RESERVED before the password hash is verified, so a parallel
 *   burst cannot get more guesses than the budget.
 * - Two budgets: a small one per (account, IP), which stops one source cold
 *   without touching the owner on another network, and a larger account-wide
 *   one against distributed guessing.
 * - Spending the account-wide budget locks the account with exponential
 *   backoff, capped (1 h by default). There is no permanent tier. The tier
 *   resets only after a quiet period (24 h by default) with no new lock. A new
 *   lock mails the owner.
 * - A correct password returns only the budget of the source that proved it
 *   (its per-(account, IP) or per-device budget), never the account-wide one.
 * - Trusted devices: a successful login gets a signed per-account device token
 *   (see device.ts). A login that presents a valid one skips the account lock
 *   and the account-wide and per-IP budgets, and spends a small budget of its
 *   own instead (5 per 15 min by default). An attacker spreading failures over
 *   many IPs can keep the account locked for everyone else, but not for the
 *   owner on a device they have signed in from before.
 * - Keys are derived from the normalised EMAIL, not the user id, so a known and
 *   an unknown address do identical counter work and get identical answers.
 *
 * Guide: Learn, "Brute force and victim lockout".
 */
import type { Clock } from './clock';
import { toMilliseconds, type Duration } from './duration';
import { sha256Hex } from './hash';
import type { CounterStore } from './stores';

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
  /** Attempts per trusted device per window. Default 5 per 15 min. */
  readonly perDevice?: RateLimitRule;
}

export interface Hit {
  readonly allowed: boolean;
  readonly count: number;
  readonly retryAfterSeconds: number;
  /** True only on the first refused hit of a window: emit one audit row per window, not one per request. */
  readonly firstRefusal: boolean;
}

export type LoginGate =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly reason: 'locked' | 'account_ip_budget' | 'device_budget';
      readonly newLock?: { until: number };
    };

/** Store key for an account derived from its normalised email. */
export function accountKey(normalizedEmail: string): string {
  return sha256Hex(`account:${normalizedEmail}`);
}

export class Throttle {
  private readonly perAccountIp: { limit: number; windowMs: number };
  private readonly perAccount: { limit: number; windowMs: number };
  private readonly perDevice: { limit: number; windowMs: number };
  private readonly baseLockMs: number;
  private readonly maxLockMs: number;
  private readonly quietPeriodMs: number;

  constructor(
    private readonly counters: CounterStore,
    private readonly clock: Clock,
    lockout: LockoutOptions = {},
  ) {
    const rule = (r: RateLimitRule | undefined, limit: number, window: Duration) => ({
      limit: r?.limit ?? limit,
      windowMs: toMilliseconds(r?.window ?? window),
    });
    this.perAccountIp = rule(lockout.perAccountIp, 5, '15m');
    this.perAccount = rule(lockout.perAccount, 10, '15m');
    this.perDevice = rule(lockout.perDevice, 5, '15m');
    this.baseLockMs = toMilliseconds(lockout.baseLock ?? '5m');
    this.maxLockMs = toMilliseconds(lockout.maxLock ?? '1h');
    this.quietPeriodMs = toMilliseconds(lockout.quietPeriod ?? '24h');
  }

  /** One hit on a fixed window. Throws when the store fails (fail closed). */
  async hit(scope: string, rule: RateLimitRule): Promise<Hit> {
    const window = await this.counters.increment(`rl:${scope}`, toMilliseconds(rule.window));
    const retryAfterSeconds = Math.max(1, Math.ceil((window.resetAt - this.clock.now()) / 1000));
    return {
      allowed: window.count <= rule.limit,
      count: window.count,
      retryAfterSeconds,
      firstRefusal: window.count === rule.limit + 1,
    };
  }

  /**
   * Call BEFORE verifying the password: checks the lock and reserves one
   * attempt. `deviceId` is the id from a device token the caller has already
   * verified for this account; such a request spends only its device budget.
   */
  async gateLogin(account: string, ip: string, deviceId?: string | null): Promise<LoginGate> {
    if (deviceId) {
      const device = await this.counters.increment(`dev:${account}:${deviceId}`, this.perDevice.windowMs);
      return device.count > this.perDevice.limit ? { allowed: false, reason: 'device_budget' } : { allowed: true };
    }
    const lock = await this.counters.get(`lock:${account}`);
    if (lock && lock.count > 0) return { allowed: false, reason: 'locked' };

    const pair = await this.counters.increment(`aip:${account}:${ip}`, this.perAccountIp.windowMs);
    if (pair.count > this.perAccountIp.limit) return { allowed: false, reason: 'account_ip_budget' };

    const all = await this.counters.increment(`acct:${account}`, this.perAccount.windowMs);
    if (all.count > this.perAccount.limit) {
      return { allowed: false, reason: 'locked', newLock: await this.lock(account) };
    }
    return { allowed: true };
  }

  /** A failed proof outside login (a wrong current password) still spends the account-wide budget. */
  async recordFailure(account: string): Promise<{ newLock?: { until: number } }> {
    const all = await this.counters.increment(`acct:${account}`, this.perAccount.windowMs);
    return all.count > this.perAccount.limit ? { newLock: await this.lock(account) } : {};
  }

  private async lock(account: string): Promise<{ until: number }> {
    // The tier's TTL is renewed on every lock, so it only decays after a full
    // quiet period without one.
    const tier = ((await this.counters.get(`tier:${account}`))?.count ?? 0) + 1;
    await this.counters.set(`tier:${account}`, tier, this.quietPeriodMs);
    const duration = Math.min(this.baseLockMs * 3 ** Math.min(tier - 1, 20), this.maxLockMs);
    const lock = await this.counters.increment(`lock:${account}`, duration);
    await this.counters.reset(`acct:${account}`);
    return { until: lock.resetAt };
  }

  /** The password was right: only the budget of the source that proved it is returned. */
  async loginSucceeded(account: string, ip: string, deviceId?: string | null): Promise<void> {
    await this.counters.reset(deviceId ? `dev:${account}:${deviceId}` : `aip:${account}:${ip}`);
  }

  /** A completed password reset proves the mailbox: lift the lock and its history. */
  async clearAccount(account: string): Promise<void> {
    await this.counters.reset(`lock:${account}`);
    await this.counters.reset(`tier:${account}`);
    await this.counters.reset(`acct:${account}`);
  }
}
