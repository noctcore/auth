/**
 * Options for the Redis stores.
 */
import type { Clock, Duration } from '@noctcore/auth';

export interface RedisStoreOptions {
  /** Key prefix. Default `auth:`. */
  readonly prefix?: string;
  readonly clock?: Clock;
}

export interface RedisSessionStoreOptions extends RedisStoreOptions {
  /**
   * How long an epoch outlives the last write to it. Must exceed the longest
   * session lifetime (remember-me, 30 d by default). Default 90 d. If it ever
   * lapses, the user's sessions fail closed (they are signed out), never open.
   * The core's device tokens and the two-factor plugin's trusted devices are
   * fenced by the epoch alone, so `createAuth` also refuses a
   * `throttle.lockout.deviceMaxAge` (30 d by default) or a
   * `trustedDevices.ttl` longer than this value.
   */
  readonly epochTtl?: Duration;
  /**
   * The longest session this store will hold: at least your remember-me TTL
   * (`session.rememberMeTtl`, 30 d by default). The store refuses to start when
   * `epochTtl` is not longer, and `createAuth` refuses a remember-me or
   * absolute TTL longer than this value.
   */
  readonly maxSessionTtl?: Duration;
}
