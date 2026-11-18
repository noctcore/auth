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
 *   backoff, capped (1 h by default). The tier resets only after a quiet
 *   period (24 h by default) with no new lock. A new lock mails the owner.
 * - Opt-in permanent tier (`lockout.permanent`): after `afterLocks` temporary
 *   locks in a row, the next lock never lapses; only `clearPermanent` (an
 *   admin) lifts it, not a password reset. It is keyed on the address like
 *   the rest, so unknown addresses reach it too. Trusted devices still get
 *   through it unless `trustedDevices` is false.
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
 * Guide: Learn, "Brute force and lockout".
 */
import { counterKeys as keys } from './counter-keys';
import {
  windowRule,
  type FactorGate,
  type Hit,
  type LockoutOptions,
  type LockState,
  type LoginGate,
  type NewLock,
  type RateLimitRule,
  type WindowRule,
} from './rules';
import type { Clock } from '../ports/clock';
import type { CounterStore } from '../ports/stores';
import { AuthConfigError } from '../shared/errors';
import { LOCKOUT_EXPIRES_AT, toMilliseconds } from '../shared/duration';

export class Throttle {
  private readonly perAccountIp: WindowRule;
  private readonly perAccount: WindowRule;
  private readonly perDevice: WindowRule;
  /** Oldest device token accepted. */
  readonly deviceMaxAgeMs: number;
  private readonly baseLockMs: number;
  private readonly maxLockMs: number;
  private readonly quietPeriodMs: number;
  /** Temporary locks in a row before the next is permanent; undefined when the tier is off. */
  private readonly permanentAfter: number | undefined;
  private readonly permanentDevices: boolean;
  /** Whether login may answer `account_locked` for a locked account. */
  readonly revealLocked: boolean;

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
    this.permanentAfter = permanentAfter(lockout);
    this.permanentDevices = lockout.permanent?.trustedDevices ?? true;
    this.revealLocked = lockout.revealLocked ?? false;
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
    // With the tier off, its key is never read: the store calls stay as they were.
    const permanent =
      this.permanentAfter !== undefined &&
      (await this.counters.get(keys.permanent(account))) !== null;

    if (permanent) {
      const held = this.held({ permanent: true });

      if (!deviceId || !this.permanentDevices)
        return { allowed: false, reason: 'permanently_locked', ...held };

      const gate = await reserveDeviceSlots(this.counters, this.perDevice, account, deviceId);

      return gate.allowed ? gate : { ...gate, ...held };
    }

    const lock = await this.counters.get(keys.lock(account));
    const locked = lock !== null && lock.count > 0;

    if (locked) {
      const held = this.held({ until: lock.resetAt });

      if (!deviceId) return { allowed: false, reason: 'locked', ...held };

      const gate = await reserveDeviceSlots(this.counters, this.perDevice, account, deviceId);

      return gate.allowed ? gate : { ...gate, ...held };
    }

    const pair = await this.counters.increment(
      keys.accountIp(account, ip),
      this.perAccountIp.windowMs,
    );

    if (pair.count > this.perAccountIp.limit)
      return { allowed: false, reason: 'account_ip_budget' };

    const all = await this.counters.increment(keys.account(account), this.perAccount.windowMs);

    if (all.count > this.perAccount.limit) {
      // Only the attempt that crossed the limit locks; a parallel one that also
      // got past the lock check above is refused here without a second lock.
      if (!locksAt(all.count, this.perAccount.limit))
        return { allowed: false, reason: 'locked', ...(await this.runningLock(account)) };

      const { newLock } = await this.lock(account, all.count, true);

      if (!newLock)
        return { allowed: false, reason: 'locked', ...(await this.runningLock(account)) };

      return {
        allowed: false,
        reason: newLock.permanent ? 'permanently_locked' : 'locked',
        newLock,
        ...this.held(newLock.permanent ? { permanent: true } : { until: newLock.until }),
      };
    }

    return { allowed: true };
  }

  /**
   * The lock detail of a refusal, attached only when login may reveal it
   * (`revealLocked`), so the default answers stay exactly as they were.
   */
  private held(lock: { until?: number; permanent?: true }): { lock?: typeof lock } {
    return this.revealLocked ? { lock } : {};
  }

  /**
   * The end of a lock set by a parallel request, read only when login may
   * reveal it (`revealLocked`), so the default path makes no extra store call.
   */
  private async runningLock(account: string): Promise<{ lock?: { until?: number } }> {
    if (!this.revealLocked) return {};

    const running = await this.counters.get(keys.lock(account));

    return { lock: running ? { until: running.resetAt } : {} };
  }

  /**
   * Call BEFORE checking a second-factor code: checks the factor's lock and
   * reserves one attempt in `account`'s budget, counted per account across
   * every IP. Spending the budget locks the factor with the same capped
   * backoff as the password lockout (`baseLock`, `maxLock`, `quietPeriod`).
   * Its keys live under their own prefix, so a factor lock never locks the
   * password and back, whatever `account` is.
   */
  async gateFactor(account: string, rule: RateLimitRule): Promise<FactorGate> {
    const scope = keys.factor(account);
    const lock = await this.counters.get(keys.lock(scope));

    if (lock !== null) return { allowed: false };

    const all = await this.counters.increment(keys.account(scope), toMilliseconds(rule.window));

    if (all.count > rule.limit) {
      if (!locksAt(all.count, rule.limit)) return { allowed: false };

      return { allowed: false, ...(await this.lock(scope, all.count, false)) };
    }

    return { allowed: true };
  }

  /** A correct second-factor code: the account's attempt budget starts over. */
  async factorSucceeded(account: string): Promise<void> {
    await this.counters.reset(keys.account(keys.factor(account)));
  }

  /** A failed proof outside login (a wrong current password) still spends the account-wide budget. */
  async recordFailure(account: string): Promise<{ newLock?: NewLock }> {
    const all = await this.counters.increment(keys.account(account), this.perAccount.windowMs);

    if (!locksAt(all.count, this.perAccount.limit)) return {};

    return this.lock(account, all.count, true);
  }

  /**
   * A wrong password let through a lock by a device token: its reserved device
   * slots stay spent, and it also counts against the account-wide budget.
   */
  async deviceFailed(account: string): Promise<{ newLock?: NewLock }> {
    return this.recordFailure(account);
  }

  /**
   * Locks `account`, or finds it already locked. The attempt counter is NOT
   * reset: it is held at `count` (already over the limit) for exactly as long
   * as the lock lasts, so a request that read "no lock" a moment before still
   * counts above the limit and is refused. Resetting it here let such requests
   * through, one fresh budget at a time, under a parallel burst.
   *
   * Only the crossing whose increment CREATES the lock (the store answers 1)
   * raises the backoff tier and reports `newLock`. A crossing that finds the
   * lock already running, from a parallel burst or a wrong password let
   * through by a device token, leaves the tier, the lock's end and the owner's
   * mailbox alone: one tier step and one notice per lock.
   *
   * With the permanent tier on and `escalates` (an account's password lock,
   * never a second factor's), the new lock that brings the tier past
   * `afterLocks` also sets the permanent marker, stored with the far-future
   * expiry so it never lapses on its own.
   */
  private async lock(
    account: string,
    count: number,
    escalates: boolean,
  ): Promise<{ newLock?: NewLock }> {
    const previous = await this.counters.get(keys.tier(account));
    const tier = (previous?.count ?? 0) + 1;
    const backoffMs = this.baseLockMs * 3 ** Math.min(tier - 1, 20);
    const duration = Math.min(backoffMs, this.maxLockMs);
    // An increment arms its TTL only on the first hit, so a running lock keeps its end.
    const lock = await this.counters.increment(keys.lock(account), duration);

    await this.counters.set(
      keys.account(account),
      count,
      Math.max(1, lock.resetAt - this.clock.now()),
    );

    if (lock.count !== 1) return {};

    // The tier's TTL is renewed on every lock, so it only decays after a full
    // quiet period without one.
    await this.counters.set(keys.tier(account), tier, this.quietPeriodMs);

    if (escalates && this.permanentAfter !== undefined && tier > this.permanentAfter) {
      // Already permanent (wrong passwords let through by a device token
      // crossed again): announced once, not on every crossing.
      if ((await this.counters.get(keys.permanent(account))) !== null) return {};

      await this.counters.set(keys.permanent(account), 1, LOCKOUT_EXPIRES_AT - this.clock.now());

      return { newLock: { until: LOCKOUT_EXPIRES_AT, permanent: true } };
    }

    return { newLock: { until: lock.resetAt } };
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

  /**
   * A completed password reset proves the mailbox: lift the temporary lock and
   * its history. A permanent lock stays: only an admin lifts it.
   */
  async clearAccount(account: string): Promise<void> {
    await this.counters.reset(keys.lock(account));
    await this.counters.reset(keys.tier(account));
    await this.counters.reset(keys.account(account));
  }

  /** The account's lock state, for an admin. Reads the permanent marker whether or not the tier is on. */
  async lockState(account: string): Promise<LockState> {
    const permanent = (await this.counters.get(keys.permanent(account))) !== null;
    const lock = await this.counters.get(keys.lock(account));
    const temporary = lock !== null && lock.count > 0;

    return {
      locked: permanent || temporary,
      permanent,
      until: !permanent && temporary ? new Date(lock.resetAt) : null,
    };
  }

  /**
   * An admin lifts every lock on the account, the permanent one included, and
   * its history: the backoff tier and the account-wide budget start over.
   * Returns the state it found.
   */
  async clearPermanent(account: string): Promise<LockState> {
    const before = await this.lockState(account);

    await this.counters.reset(keys.permanent(account));
    await this.clearAccount(account);

    return before;
  }
}

/** The validated `permanent.afterLocks`, or undefined when the tier is off. */
function permanentAfter(lockout: LockoutOptions): number | undefined {
  if (!lockout.permanent) return undefined;

  const { afterLocks } = lockout.permanent;

  if (!Number.isInteger(afterLocks) || afterLocks < 1) {
    throw new AuthConfigError(
      'throttle.lockout.permanent.afterLocks must be an integer of at least 1',
    );
  }

  return afterLocks;
}

/**
 * Whether the attempt that brought the counter to `count` crosses the limit.
 * The counter is never reset by a lock (see `lock`), so the first crossing
 * comes at `limit + 1` and, while the lock lasts, every further `limit + 1`
 * failures (a wrong password let through by a device token, or requests that
 * read "no lock" just before it was set) cross again. Exactly one attempt sees
 * each crossing count, so no extra guesses get through. A crossing under a
 * running lock finds it there and does not raise the tier (see `lock`).
 */
function locksAt(count: number, limit: number): boolean {
  // Counts start at 1, so the multiples of `limit + 1` are exactly those crossings.
  return count % (limit + 1) === 0;
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
