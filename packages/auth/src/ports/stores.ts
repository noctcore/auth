/**
 * The storage interfaces. The core never talks to a database: it is handed
 * these, and any implementation that passes the conformance suite in
 * `@noctcore/auth/testing` is a valid one. The suite checks the properties the
 * flows rely on, which are listed on each method.
 *
 * Guide: Build, "Writing a store adapter".
 */
import type { NormalizedEmail } from '../shared/email';

/**
 * A user id no store issues (it starts with U+2205, outside any id alphabet).
 * Flows look it up for unknown accounts so they make the same store calls.
 */
export const NO_SUCH_USER_ID = '\u2205no-such-user';

export interface AuthUser {
  readonly id: string;
  readonly email: string;
  readonly emailVerified: boolean;
}

export type WithPasswordHash<U> = U & { readonly passwordHash: string | null };

/**
 * What `UserStore.changeEmail` did: `changed`; `taken` when another user, live
 * or soft-deleted, holds the address (a unique violation is never thrown); or
 * `stale` when the user is missing, soft-deleted or no longer has `from`.
 */
export type EmailChangeResult = 'changed' | 'taken' | 'stale';

export interface UserStore<U extends AuthUser = AuthUser> {
  /**
   * Live users only: a soft-deleted user is not found. Must match the address
   * exactly, byte for byte: a case- or accent-insensitive lookup (a database
   * collation) would find one row under several spellings. The core also
   * treats a row whose `email` differs from the address asked for as not found.
   */
  findCredentialByEmail(email: NormalizedEmail): Promise<WithPasswordHash<U> | null>;
  findCredentialById(id: string): Promise<WithPasswordHash<U> | null>;
  findById(id: string): Promise<U | null>;
  /** Null when the email is already taken. A unique violation is never thrown. */
  create(input: { email: NormalizedEmail; passwordHash: string }): Promise<U | null>;
  /**
   * Guarded: false (and nothing written) when the user is missing or
   * soft-deleted. With `expected` it is a compare-and-set: the write happens
   * only if the stored hash still equals `expected` (null for no password), in
   * one statement, so a rehash can never overwrite a password changed meanwhile.
   */
  setPasswordHash(
    id: string,
    passwordHash: string,
    options?: { readonly expected?: string | null },
  ): Promise<boolean>;
  /** Guarded on the stored email still equalling `email`, so a stale link cannot verify a changed address. */
  markEmailVerified(id: string, email: NormalizedEmail): Promise<boolean>;
  /**
   * Moves the user to the address `to`, marks it verified and, with
   * `clearPassword`, removes the password hash, in one statement, as a
   * compare-and-set on the stored email still equalling `from`. The address
   * stays unique: of two users changing to one address at once, exactly one
   * gets `changed`. `to` may equal `from`: the revert uses that to remove the
   * password alone when the old address has an account again. Optional, so
   * stores written before it still compile; the email change flows need it
   * and throw `AuthConfigError` without it.
   */
  changeEmail?(
    id: string,
    change: {
      readonly from: NormalizedEmail;
      readonly to: NormalizedEmail;
      readonly clearPassword?: boolean;
    },
  ): Promise<EmailChangeResult>;
}

export interface StoredSession<A = unknown> {
  /** SHA-256 of the cookie token. The token itself is never stored. */
  readonly id: string;
  readonly userId: string;
  readonly createdAt: number;
  /** When the user last proved a credential; drives `requireFreshAuth`. */
  readonly authenticatedAt: number;
  readonly lastActiveAt: number;
  /** Absolute end, also enforced by the store's TTL. */
  readonly expiresAt: number;
  readonly idleTimeoutMs: number;
  /** The user's revocation epoch captured before the credential was read. */
  readonly epoch: number;
  readonly rememberMe: boolean;
  readonly persistentCookie: boolean;
  readonly ip: string;
  readonly userAgent: string;
  readonly attributes: A;
}

export interface SessionStore {
  /**
   * Longest session TTL this store can guard (for example a revocation epoch
   * that must outlive every session). `createAuth` refuses a session config
   * whose remember-me or absolute TTL is longer. Omit when there is no limit.
   */
  readonly maxSessionTtlMs?: number;
  /**
   * How long the store keeps a user's revocation epoch after its last write,
   * for a store that forgets it (and then reads it as 0). Device tokens and
   * trusted devices are fenced by the epoch alone, so `createAuth` refuses a
   * `throttle.lockout.deviceMaxAge`, and the two-factor plugin a
   * `trustedDevices.ttl`, that is not at least `DEVICE_CLOCK_SKEW_MS` (a
   * minute) shorter. Omit when the epoch never lapses; a value that is not a
   * positive number is refused.
   */
  readonly epochTtlMs?: number;
  /** Stores the session with a TTL of `ttlMs` and indexes it under its user. */
  create(session: StoredSession, ttlMs: number): Promise<void>;
  get(id: string): Promise<StoredSession | null>;
  /**
   * Replaces the stored value ONLY IF the session still exists, keeping its
   * TTL (Redis: `SET ... XX KEEPTTL`). Returns false when it is gone. Must
   * never recreate a deleted session, even when racing a delete.
   */
  touch(session: StoredSession): Promise<boolean>;
  /**
   * Deletes the sessions and removes them from the user's index. Should
   * return the ids this call removed (the ones that still existed), so that of
   * concurrent deletes of one session exactly one reports it: the per-user cap
   * reports evictions from it. A store that returns nothing is taken to have
   * removed every id it was given, and racing evictions may then report a
   * session twice.
   */
  delete(userId: string, ids: readonly string[]): Promise<void | readonly string[]>;
  /** The user's sessions that still exist (expired ones are not returned). */
  listByUser(userId: string): Promise<StoredSession[]>;
  /** The user's revocation epoch; 0 when never bumped. */
  getEpoch(userId: string): Promise<number>;
  /** Atomically increments and returns the epoch. Its TTL must outlive every session. */
  bumpEpoch(userId: string): Promise<number>;
}

export interface StoredToken {
  readonly purpose: string;
  readonly userId: string;
  /** SHA-256 of a link token, or an HMAC of a short code. */
  readonly hash: string;
  readonly expiresAt: number;
  readonly attempts: number;
  readonly data: Readonly<Record<string, string>>;
}

export interface TokenStore {
  /** Stores the token, replacing any token of the same purpose for the same user. Concurrent puts never throw. */
  put(token: StoredToken): Promise<void>;
  find(purpose: string, hash: string): Promise<StoredToken | null>;
  findByUser(purpose: string, userId: string): Promise<StoredToken | null>;
  /** Atomically removes and returns the token: of many concurrent callers exactly one gets it. */
  consume(purpose: string, hash: string): Promise<StoredToken | null>;
  /**
   * Atomically increments the attempt count of the user's token of that purpose
   * if it is below `max`, returning the new count; null when it is missing or
   * already at `max`. Of N concurrent callers at most `max` get a number.
   */
  incrementAttempts(purpose: string, userId: string, max: number): Promise<number | null>;
  /** Deletes the user's tokens, of the given purposes or of every purpose. */
  deleteByUser(userId: string, purposes?: readonly string[]): Promise<void>;
}

export interface CounterWindow {
  readonly count: number;
  /** When the window ends, in ms since the epoch. */
  readonly resetAt: number;
}

export interface CounterStore {
  /**
   * Increments the counter. The first hit arms a TTL of `windowMs`; later hits
   * never extend it. Every key has a TTL, always. Of N concurrent callers each
   * sees a distinct count.
   */
  increment(key: string, windowMs: number): Promise<CounterWindow>;
  get(key: string): Promise<CounterWindow | null>;
  /** Overwrites the counter with `count` and a fresh TTL of `windowMs`. */
  set(key: string, count: number, windowMs: number): Promise<void>;
  /**
   * Takes one back: atomically lowers the counter by 1, never below 0, keeping
   * its TTL. A missing key stays missing. Used to refund a reserved attempt.
   */
  decrement(key: string): Promise<void>;
  reset(key: string): Promise<void>;
}
