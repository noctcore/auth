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
 *   backoff, capped (1 h by default), or with the app's own `durations`
 *   ladder (the last entry repeats). The tier resets only after a quiet
 *   period (24 h by default) with no new lock. A new lock mails the owner.
 * - Opt-in permanent tier (`lockout.permanent`): after `afterLocks` temporary
 *   locks in a row (a completed sign-in, every factor proved, or a
 *   completed password reset resets the count; a correct password with a
 *   second factor still owed does not), the next lock
 *   never lapses; only `clearPermanent` (an admin) lifts it, not a password
 *   reset. Its marker is keyed on the user id when the address has an
 *   account, so it follows the account through an email change, and on the
 *   address otherwise, so unknown addresses reach it too (a sign-up on the
 *   address clears that one). Trusted devices still get through it unless
 *   `trustedDevices` is false.
 * - A correct password returns only the budget of the source that proved it
 *   (its per-(account, IP) or per-device budget), never the account-wide one,
 *   unless `countSuccesses` is false: then the account-wide slot comes back
 *   too, but only once the sign-in completes (`signInCompleted`), matched by
 *   count and never more slots than correct passwords reserved in the
 *   current window.
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
  assertWindowRule,
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
import type { CounterStore, CounterWindow } from '../ports/stores';
import {
  assertBoolean,
  assertList,
  assertOneOf,
  configMilliseconds,
} from '../shared/config-checks';
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
  /** The `durations` ladder in ms, used in place of `baseLock` and `maxLock`; undefined when not set. */
  private readonly lockLadderMs: readonly number[] | undefined;
  private readonly quietPeriodMs: number;
  /** Temporary locks in a row before the next is permanent; undefined when the tier is off. */
  private readonly permanentAfter: number | undefined;
  /** Whether trusted devices get through a permanent lock (`permanent.trustedDevices`). */
  readonly permanentDevices: boolean;
  /** Whether login may answer `account_locked` for a locked account. */
  readonly revealLocked: boolean;
  /**
   * Whether a correct password keeps spending the account-wide budget
   * (`countSuccesses`, default true). False: a completed sign-in hands the
   * slot back, so only failures count.
   */
  readonly countSuccesses: boolean;
  /**
   * What bounds a password proved again from a live session (`sessionProofs`,
   * default `'lockout'`): login's budgets, or only the door's own limit.
   */
  readonly sessionProofs: 'lockout' | 'door';

  constructor(
    private readonly counters: CounterStore,
    private readonly clock: Clock,
    lockout?: LockoutOptions | null,
  ) {
    // A default parameter replaces only undefined: null must give the defaults too.
    const options = lockout ?? {};
    const name = (key: string): string => `throttle.lockout.${key}`;

    this.perAccountIp = windowRule(name('perAccountIp'), options.perAccountIp, 5, '15m');
    this.perAccount = windowRule(name('perAccount'), options.perAccount, 10, '15m');
    this.perDevice = windowRule(name('perDevice'), options.perDevice, 5, '15m');
    this.deviceMaxAgeMs = configMilliseconds(name('deviceMaxAge'), options.deviceMaxAge, '30d');
    this.baseLockMs = configMilliseconds(name('baseLock'), options.baseLock, '5m');
    this.maxLockMs = configMilliseconds(name('maxLock'), options.maxLock, '1h');
    this.quietPeriodMs = configMilliseconds(name('quietPeriod'), options.quietPeriod, '24h');
    this.permanentAfter = permanentAfter(options);
    this.permanentDevices = options.permanent?.trustedDevices ?? true;
    this.revealLocked = options.revealLocked ?? false;
    this.countSuccesses = options.countSuccesses ?? true;
    this.sessionProofs = options.sessionProofs ?? 'lockout';
    this.lockLadderMs = lockLadder(options);

    assertLockoutOptions(options, [
      ['perAccountIp', this.perAccountIp],
      ['perAccount', this.perAccount],
      ['perDevice', this.perDevice],
    ]);

    // A lock of zero would never be in force, so the lockout would only count.
    if (this.baseLockMs <= 0)
      throw new AuthConfigError('throttle.lockout.baseLock must be longer than zero');
    if (this.maxLockMs <= 0)
      throw new AuthConfigError('throttle.lockout.maxLock must be longer than zero');
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
   * `loginSucceeded` hands both slots back. `owner` is the id of the
   * address's account, if it has one: the permanent marker is read and set
   * under it, so known and unknown addresses each read one key.
   */
  async gateLogin(
    account: string,
    ip: string,
    deviceId?: string | null,
    owner?: string | null,
  ): Promise<LoginGate> {
    // With the tier off, its key is never read: the store calls stay as they were.
    const permanent =
      this.permanentAfter !== undefined &&
      (await this.counters.get(this.permanentKey(account, owner))) !== null;

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

    const all = await this.countAttempt(account);

    if (all.count > this.perAccount.limit) {
      // Only the attempt that crossed the limit locks; a parallel one that also
      // got past the lock check above is refused here without a second lock.
      if (!locksAt(all.count, this.perAccount.limit)) return this.racingRefusal(account, owner);

      const { newLock } = await this.lock(account, all.count, true, owner);

      if (!newLock) return this.racingRefusal(account, owner);

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
  private held(lock: { readonly until: number } | { readonly permanent: true }): {
    lock?: typeof lock;
  } {
    return this.revealLocked ? { lock } : {};
  }

  /** A refusal under a lock a parallel request set (or found): permanent when the marker says so. */
  private async racingRefusal(account: string, owner?: string | null): Promise<LoginGate> {
    const running = await this.runningLock(account, owner);
    const permanent = running.lock !== undefined && 'permanent' in running.lock;

    return { allowed: false, reason: permanent ? 'permanently_locked' : 'locked', ...running };
  }

  /**
   * The end of a lock set by a parallel request, read only when login may
   * reveal it (`revealLocked`), so the default path makes no extra store call.
   * A permanent marker set by a parallel request (with the tier on) makes the
   * answer permanent. Otherwise a lock that cannot be read (it ended between
   * the two reads) is answered as a temporary one of `baseLock`: only the
   * permanent marker makes an answer permanent.
   */
  private async runningLock(
    account: string,
    owner?: string | null,
  ): Promise<{ lock?: { until: number } | { permanent: true } }> {
    if (!this.revealLocked) return {};

    if (
      this.permanentAfter !== undefined &&
      (await this.counters.get(this.permanentKey(account, owner))) !== null
    )
      return { lock: { permanent: true } };

    const running = await this.counters.get(keys.lock(account));

    return { lock: { until: running?.resetAt ?? this.clock.now() + this.lockDuration(1) } };
  }

  /** Where the permanent marker lives: under the account when there is one, else the address. */
  private permanentKey(account: string, owner?: string | null): string {
    return owner ? keys.permanentUser(owner) : keys.permanent(account);
  }

  /** Whether the opt-in permanent tier is on. */
  get permanentTier(): boolean {
    return this.permanentAfter !== undefined;
  }

  /** Whether the permanent tier holds this account. Reads nothing while the tier is off. */
  async isPermanentlyLocked(userId: string): Promise<boolean> {
    if (this.permanentAfter === undefined) return false;

    return (await this.counters.get(keys.permanentUser(userId))) !== null;
  }

  /**
   * An account was just created (or found taken) for this address: a
   * permanent marker the address took while it had no account must not pass
   * to the new owner. Called on every sign-up, so a taken and a new address
   * do the same work; an existing account's marker is under its user id and
   * is not touched.
   */
  async addressSignedUp(account: string): Promise<void> {
    if (this.permanentAfter === undefined) return;

    await this.counters.reset(keys.permanent(account));
  }

  /**
   * Call BEFORE checking a second-factor code: checks the factor's lock and
   * reserves one attempt in `account`'s budget, counted per account across
   * every IP. Spending the budget locks the factor with the same backoff as
   * the password lockout (`baseLock` and `maxLock`, or `durations`, and
   * `quietPeriod`), counted in the factor's own tier.
   * Its keys live under their own prefix, so a factor lock never locks the
   * password and back, whatever `account` is. A new lock (`newLock`) does not
   * count toward the permanent tier by itself: pass it on to `escalate` (the
   * two-factor plugin does, through `context.escalateLock`).
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

  /**
   * Claims the rotation of a user's imported recovery code set for
   * `windowMs`: true for the first caller in the window, false for every
   * other (an atomic increment). Throws when the store fails.
   */
  async claimRecoveryCodeRotation(userId: string, windowMs: number): Promise<boolean> {
    const window = await this.counters.increment(keys.recoveryCodeRotation(userId), windowMs);

    return window.count === 1;
  }

  /** A correct second-factor code: the account's attempt budget starts over. */
  async factorSucceeded(account: string): Promise<void> {
    await this.counters.reset(keys.account(keys.factor(account)));
  }

  /**
   * A failed proof with no attempt reserved by `gateLogin` still spends the
   * account-wide budget. This only counts: a `newLock` it returns is not
   * announced. Outside the package, call `context.recordFailedProof`, which
   * also carries the lock out like a password lock (the owner's notice, the
   * audit row and, in the permanent tier, the end of the sessions).
   */
  async recordFailure(account: string, owner?: string | null): Promise<{ newLock?: NewLock }> {
    const all = await this.countAttempt(account);

    if (!locksAt(all.count, this.perAccount.limit)) return {};

    return this.lock(account, all.count, true, owner);
  }

  /**
   * A wrong password let through a lock by a device token: its reserved device
   * slots stay spent, and it also counts against the account-wide budget.
   */
  async deviceFailed(account: string, owner?: string | null): Promise<{ newLock?: NewLock }> {
    return this.recordFailure(account, owner);
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
   * With the permanent tier on and `escalates` (an account's password lock;
   * a second factor's lock counts only through `escalate`), each new lock
   * also counts toward the tier (`countTowardPermanent`), and the lock that
   * brings it past `afterLocks` sets the permanent marker under `owner` (or
   * the address), stored with the far-future expiry so it never lapses on
   * its own.
   */
  private async lock(
    account: string,
    count: number,
    escalates: boolean,
    owner?: string | null,
  ): Promise<{ newLock?: NewLock }> {
    const previous = await this.counters.get(keys.tier(account));
    const tier = (previous?.count ?? 0) + 1;
    const duration = this.lockDuration(tier);
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

    if (escalates) {
      const escalated = await this.countTowardPermanent(account, owner);

      // Already permanent (wrong passwords let through by a device token
      // crossed again): announced once, not on every crossing.
      if (escalated.permanent) return escalated.newLock ? { newLock: escalated.newLock } : {};
    }

    return { newLock: { until: lock.resetAt } };
  }

  /**
   * How long lock number `tier` (from 1) lasts: entry `tier` of the
   * `durations` ladder, its last entry once the ladder runs out, or else
   * `baseLock` multiplied by 3 per earlier lock, capped at `maxLock`.
   */
  private lockDuration(tier: number): number {
    // Entry `tier`, or the last one: the ladder is never empty (startup refuses that).
    if (this.lockLadderMs)
      return this.lockLadderMs.reduce((pick, entry, index) => (index < tier ? entry : pick));

    const backoffMs = this.baseLockMs * 3 ** Math.min(tier - 1, 20);

    return Math.min(backoffMs, this.maxLockMs);
  }

  /**
   * A new lock raised outside the password gate (a second factor's own gate,
   * which never escalates by itself) counts toward the permanent tier of the
   * address `account` (its account `owner`), in the same counter as the
   * password locks. Call it once per NEW lock, never per refusal. Returns the
   * permanent lock when this one brought the count past `afterLocks`, and
   * nothing while the tier is off, below it, or already permanent.
   *
   * Prefer `context.escalateLock`, which also carries the permanent lock out
   * (the owner's notice, the audit row, the end of the sessions).
   */
  async escalate(account: string, owner?: string | null): Promise<{ newLock?: NewLock }> {
    const escalated = await this.countTowardPermanent(account, owner);

    return escalated.newLock ? { newLock: escalated.newLock } : {};
  }

  /**
   * One more lock in a row toward the permanent tier, renewed like the
   * backoff tier but reset by a completed sign-in. `permanent` when the
   * account is (now or already) past `afterLocks`; `newLock` only for the
   * lock that set the marker, so a permanent lock is announced once.
   */
  private async countTowardPermanent(
    account: string,
    owner?: string | null,
  ): Promise<{ permanent: boolean; newLock?: NewLock }> {
    if (this.permanentAfter === undefined) return { permanent: false };

    const inARow = ((await this.counters.get(keys.escalation(account)))?.count ?? 0) + 1;

    await this.counters.set(keys.escalation(account), inARow, this.quietPeriodMs);

    if (inARow <= this.permanentAfter) return { permanent: false };

    const marker = this.permanentKey(account, owner);

    if ((await this.counters.get(marker)) !== null) return { permanent: true };

    await this.counters.set(marker, 1, LOCKOUT_EXPIRES_AT - this.clock.now());

    return { permanent: true, newLock: { until: LOCKOUT_EXPIRES_AT, permanent: true } };
  }

  /**
   * The password was right: only the budget of the source that proved it is
   * returned. Pass `deviceId` only for a `viaDevice` attempt: both of its
   * reserved device slots (its own and the shared one) come back.
   *
   * With `countSuccesses` false, an attempt that reserved an account-wide
   * slot (not a `viaDevice` one) is also recorded as owed one slot back, in
   * a counter `countAttempt` clears when the account-wide counter answers 1. The slot itself
   * comes back only when the sign-in completes (`signInCompleted`), or at
   * once at a door that proves nothing more (`refundSuccess`).
   *
   * It does NOT start the count toward the permanent tier over: a second
   * factor may still be owed, and an attacker who holds the password would
   * otherwise reset the climb before every round of guessed codes. Only a
   * completed sign-in does (`signInCompleted`).
   */
  async loginSucceeded(account: string, ip: string, deviceId?: string | null): Promise<void> {
    if (deviceId) {
      await this.counters.decrement(keys.device(account, deviceId));
      await this.counters.decrement(keys.devices(account));

      return;
    }

    await this.counters.reset(keys.accountIp(account, ip));

    if (!this.countSuccesses) await this.owe(account);
  }

  /**
   * A sign-in completed, every factor proved and the session about to be
   * issued: the locks in a row toward the permanent tier start over (the
   * temporary backoff does not), and with `countSuccesses` false one owed
   * account-wide slot comes back (`refundSuccess`). Reads and writes nothing
   * while the tier is off and successes count.
   */
  async signInCompleted(account: string): Promise<void> {
    if (this.permanentAfter !== undefined) await this.counters.reset(keys.escalation(account));

    await this.refundSuccess(account);
  }

  /**
   * With `countSuccesses` false, hands back one account-wide slot a correct
   * password reserved (`loginSucceeded`) and has not had back yet. Login
   * calls it through `signInCompleted`, so a correct password with a second
   * factor still owed gets nothing back until the factor is proved;
   * `reauthenticate` and `changePassword` call it right after the correct
   * password, since their caller holds a session from a completed sign-in.
   *
   * Refunds are matched by count, not to the attempt that earned them, and
   * capped per account-wide window: each refund claims a number from a second
   * counter and goes ahead only while the claims stay within the slots owed
   * in the current window, so parallel completions never hand back more than
   * correct passwords reserved in it, and the store never takes the budget
   * below zero. A completion that reserved nothing of its own (a challenge
   * opened in an earlier window, a device sign-in) can take a slot another
   * correct password in the window is owed, never one more. The window that
   * starts once the account-wide counter lapses clears both counters
   * (`countAttempt`), so a slot owed in an earlier window, or in one a lock
   * re-armed, never comes back out of a newer one.
   *
   * Not atomic: a completion racing the first attempt of a new window (the
   * clear lands between the read of what is owed and the claim), or racing a
   * password reset (`clearAccount`), can hand back one slot of the new
   * budget. Reads and writes nothing while successes count.
   */
  async refundSuccess(account: string): Promise<void> {
    if (this.countSuccesses) return;

    const owed = await this.counters.get(keys.owed(account));

    if (owed === null || owed.count <= 0) return;

    const claimKey = keys.refunded(account);
    const claim = await this.counters.increment(claimKey, this.msUntil(owed.resetAt));

    if (claim.count > owed.count) {
      await this.counters.decrement(claimKey);

      return;
    }

    await this.counters.decrement(keys.account(account));
  }

  /**
   * One attempt against the account-wide budget. With `countSuccesses` false,
   * an attempt the counter answers 1 also clears the slots owed back and the
   * refunds claimed. That is the first attempt of a new window, whose owed
   * slots belong to the window that lapsed whatever their own expiry says (a
   * lock re-arms the account-wide counter to the lock's end, so the two drift
   * apart). It is also an attempt mid-window after refunds brought the
   * counter back to 0 (a decrement keeps the key): then a pending challenge's
   * slot may not come back, which errs toward counting.
   */
  private async countAttempt(account: string): Promise<CounterWindow> {
    const all = await this.counters.increment(keys.account(account), this.perAccount.windowMs);

    if (!this.countSuccesses && all.count === 1) await this.forgetOwed(account);

    return all;
  }

  /** Clears the slots owed back and the refunds claimed against them. */
  private async forgetOwed(account: string): Promise<void> {
    await this.counters.reset(keys.owed(account));
    await this.counters.reset(keys.refunded(account));
  }

  /**
   * One more account-wide slot owed back. Its expiry follows the account-wide
   * counter as it stands; `countAttempt` clears it when a new window opens.
   * Nothing is owed when the window has already ended (its slot went with it).
   */
  private async owe(account: string): Promise<void> {
    const all = await this.counters.get(keys.account(account));

    if (all === null) return;

    await this.counters.increment(keys.owed(account), this.msUntil(all.resetAt));
  }

  /** The time left until `at`, at least 1 ms, as a TTL. */
  private msUntil(at: number): number {
    return Math.max(1, at - this.clock.now());
  }

  /**
   * A completed password reset proves the mailbox: lift the temporary lock and
   * its history, and the count toward the permanent tier. A permanent lock
   * stays: only an admin lifts it.
   */
  async clearAccount(account: string): Promise<void> {
    await this.counters.reset(keys.lock(account));
    await this.counters.reset(keys.tier(account));
    await this.counters.reset(keys.account(account));

    if (this.permanentAfter !== undefined) await this.counters.reset(keys.escalation(account));

    if (this.countSuccesses) return;

    // The slots owed back belong to the budget just reset: a new window must
    // not have its failures handed back.
    await this.forgetOwed(account);
  }

  /**
   * The lock state of an address (and its account, `owner`, if it has one),
   * for an admin. Reads the permanent marker whether or not the tier is on.
   */
  async lockState(account: string, owner?: string | null): Promise<LockState> {
    const permanent = (await this.counters.get(this.permanentKey(account, owner))) !== null;
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
   * Returns the state it found. Not atomic: a burst of failures running
   * during the clear can lock the account again as soon as it is lifted.
   */
  async clearPermanent(account: string, owner?: string | null): Promise<LockState> {
    const before = await this.lockState(account, owner);

    if (owner) await this.counters.reset(keys.permanentUser(owner));

    await this.counters.reset(keys.permanent(account));
    await this.counters.reset(keys.escalation(account));
    await this.clearAccount(account);

    return before;
  }
}

/**
 * The lockout's rules and booleans as `createAuth` reads them from the config:
 * a string "false" would read as on, and a `NaN` limit would never lock.
 */
function assertLockoutOptions(
  lockout: LockoutOptions,
  rules: readonly (readonly [string, WindowRule])[],
): void {
  for (const [key, rule] of rules) assertWindowRule(`throttle.lockout.${key}`, rule);

  assertBoolean('throttle.lockout.revealLocked', lockout.revealLocked);
  assertBoolean('throttle.lockout.countSuccesses', lockout.countSuccesses);
  assertOneOf('throttle.lockout.sessionProofs', lockout.sessionProofs, ['lockout', 'door']);
  assertBoolean('throttle.lockout.permanent.trustedDevices', lockout.permanent?.trustedDevices);
}

/**
 * The validated `durations` ladder in milliseconds, or undefined when it is
 * left out. Refuses a list that is empty, has an entry that is not a
 * duration or is zero, or is set together with `baseLock` or `maxLock`
 * (one of the two would be silently ignored).
 */
function lockLadder(lockout: LockoutOptions): readonly number[] | undefined {
  const { durations } = lockout;
  const name = 'throttle.lockout.durations';

  if (durations === undefined || durations === null) return undefined;

  assertList(name, durations);

  if (durations.length === 0) throw new AuthConfigError(`${name} must list at least one duration`);

  if (
    (lockout.baseLock !== undefined && lockout.baseLock !== null) ||
    (lockout.maxLock !== undefined && lockout.maxLock !== null)
  ) {
    throw new AuthConfigError(
      `${name} replaces throttle.lockout.baseLock and maxLock: set durations or those two, not both`,
    );
  }

  return Array.from(durations, (entry, index) => {
    const path = `${name}[${index}]`;
    // A NaN fallback: an entry left out (a null) is refused like any non-duration.
    const ms = configMilliseconds(path, entry, Number.NaN);

    if (ms <= 0) throw new AuthConfigError(`${path} must be longer than zero`);

    return ms;
  });
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
