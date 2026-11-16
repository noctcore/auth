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
 * - Trusted devices: every issued session carries a signed device token bound
 *   to the user, their revocation epoch and an issue time (see device-token.ts).
 *   The token matters only while the account is LOCKED: an unlocked account
 *   takes the normal path whatever the request carries, so the owner never
 *   spends a device budget by signing in. Under a lock, a valid token is not
 *   refused, but the bypass only ever helps a CORRECT password: before the
 *   verify, the attempt reserves a slot in the token's own budget AND in a
 *   budget shared by all of the account's tokens (5 per 15 min each by
 *   default), so even a parallel burst over many tokens gets at most 5 checks.
 *   A correct password hands both slots back; a wrong one keeps them and also
 *   counts against the account-wide budget, like any other failure.
 *   Holding many tokens adds no guesses, and a password change, a reset or
 *   revoke-all voids every token. An attacker spreading failures over many IPs can keep
 *   the account locked for everyone else, but not for the owner on a device
 *   they have fully signed in from since the last revocation.
 * - Keys are derived from the normalised EMAIL, not the user id, so a known and
 *   an unknown address do identical counter work and get identical answers.
 *
 * Guide: Learn, "Brute force and victim lockout".
 */
import { counterKeys as keys } from './counter-keys';
import {
  windowRule,
  type Hit,
  type LockoutOptions,
  type LoginGate,
  type RateLimitRule,
  type WindowRule,
} from './rules';
import type { Clock } from '../ports/clock';
import type { CounterStore } from '../ports/stores';
import { toMilliseconds } from '../shared/duration';

export class Throttle {
  private readonly perAccountIp: WindowRule;
  private readonly perAccount: WindowRule;
  private readonly perDevice: WindowRule;
  /** Oldest device token accepted. */
  readonly deviceMaxAgeMs: number;
  private readonly baseLockMs: number;
  private readonly maxLockMs: number;
  private readonly quietPeriodMs: number;

  constructor(
    private readonly counters: CounterStore,
    private readonly clock: Clock,
    lockout: LockoutOptions = {},
  ) {
    this.perAccountIp = windowRule(lockout.perAccountIp, 5, '15m');
    this.perAccount = windowRule(lockout.perAccount, 10, '15m');
    this.perDevice = windowRule(lockout.perDevice, 5, '15m');
    this.deviceMaxAgeMs = toMilliseconds(lockout.deviceMaxAge ?? '30d');
    this.baseLockMs = toMilliseconds(lockout.baseLock ?? '5m');
    this.maxLockMs = toMilliseconds(lockout.maxLock ?? '1h');
    this.quietPeriodMs = toMilliseconds(lockout.quietPeriod ?? '24h');
  }

  /** One hit on a fixed window. Throws when the store fails (fail closed). */
  async hit(scope: string, rule: RateLimitRule): Promise<Hit> {
    const windowMs = toMilliseconds(rule.window);
    const window = await this.counters.increment(keys.rateLimit(scope), windowMs);
    const secondsLeft = Math.ceil((window.resetAt - this.clock.now()) / 1000);

    return {
      allowed: window.count <= rule.limit,
      count: window.count,
      retryAfterSeconds: Math.max(1, secondsLeft),
      firstRefusal: window.count === rule.limit + 1,
    };
  }

  /**
   * Call BEFORE verifying the password: checks the lock and reserves one
   * attempt. `deviceId` is the id from a device token the caller has already
   * verified for this account. It is used only while the account is locked:
   * then the request reserves a slot in the device's own budget and in the
   * budget shared by all the account's devices, and comes back with
   * `viaDevice`. If its password proves wrong, call `deviceFailed`; if right,
   * `loginSucceeded` hands both slots back.
   */
  async gateLogin(account: string, ip: string, deviceId?: string | null): Promise<LoginGate> {
    const lock = await this.counters.get(keys.lock(account));
    const locked = lock !== null && lock.count > 0;

    if (locked) {
      if (!deviceId) return { allowed: false, reason: 'locked' };

      return reserveDeviceSlots(this.counters, this.perDevice, account, deviceId);
    }

    const pair = await this.counters.increment(
      keys.accountIp(account, ip),
      this.perAccountIp.windowMs,
    );

    if (pair.count > this.perAccountIp.limit)
      return { allowed: false, reason: 'account_ip_budget' };

    const all = await this.counters.increment(keys.account(account), this.perAccount.windowMs);

    if (all.count > this.perAccount.limit) {
      return { allowed: false, reason: 'locked', newLock: await this.lock(account) };
    }

    return { allowed: true };
  }

  /** A failed proof outside login (a wrong current password) still spends the account-wide budget. */
  async recordFailure(account: string): Promise<{ newLock?: { until: number } }> {
    const all = await this.counters.increment(keys.account(account), this.perAccount.windowMs);

    if (all.count <= this.perAccount.limit) return {};

    return { newLock: await this.lock(account) };
  }

  /**
   * A wrong password let through a lock by a device token: its reserved device
   * slots stay spent, and it also counts against the account-wide budget.
   */
  async deviceFailed(account: string): Promise<{ newLock?: { until: number } }> {
    return this.recordFailure(account);
  }

  private async lock(account: string): Promise<{ until: number }> {
    // The tier's TTL is renewed on every lock, so it only decays after a full
    // quiet period without one.
    const previous = await this.counters.get(keys.tier(account));
    const tier = (previous?.count ?? 0) + 1;

    await this.counters.set(keys.tier(account), tier, this.quietPeriodMs);

    const backoffMs = this.baseLockMs * 3 ** Math.min(tier - 1, 20);
    const duration = Math.min(backoffMs, this.maxLockMs);
    const lock = await this.counters.increment(keys.lock(account), duration);

    await this.counters.reset(keys.account(account));

    return { until: lock.resetAt };
  }

  /**
   * The password was right: only the budget of the source that proved it is
   * returned. Pass `deviceId` only for a `viaDevice` attempt: both of its
   * reserved device slots (its own and the shared one) come back.
   */
  async loginSucceeded(account: string, ip: string, deviceId?: string | null): Promise<void> {
    if (!deviceId) return this.counters.reset(keys.accountIp(account, ip));

    await this.counters.decrement(keys.device(account, deviceId));
    await this.counters.decrement(keys.devices(account));
  }

  /** A completed password reset proves the mailbox: lift the lock and its history. */
  async clearAccount(account: string): Promise<void> {
    await this.counters.reset(keys.lock(account));
    await this.counters.reset(keys.tier(account));
    await this.counters.reset(keys.account(account));
  }
}

/**
 * Both slots are reserved atomically before the verify, so a parallel burst
 * over any number of tokens gets no more than the shared budget. A refused
 * attempt hands its reservations back at once.
 */
async function reserveDeviceSlots(
  counters: CounterStore,
  perDevice: WindowRule,
  account: string,
  deviceId: string,
): Promise<LoginGate> {
  const ownKey = keys.device(account, deviceId);
  const sharedKey = keys.devices(account);
  const own = await counters.increment(ownKey, perDevice.windowMs);

  if (own.count > perDevice.limit) {
    await counters.decrement(ownKey);

    return { allowed: false, reason: 'device_budget' };
  }

  const shared = await counters.increment(sharedKey, perDevice.windowMs);

  if (shared.count > perDevice.limit) {
    await counters.decrement(sharedKey);
    await counters.decrement(ownKey);

    return { allowed: false, reason: 'device_budget' };
  }

  return { allowed: true, viaDevice: true };
}
