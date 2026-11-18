/**
 * Results instead of exceptions, and public codes that never reveal account
 * state.
 *
 * Every flow returns an `AuthResult`. A refusal carries two things: `code`,
 * the only part that may reach the client, from a closed set designed so that
 * "no such account", "wrong password" and "locked" all read the same; and
 * `reason`, the internal cause for the audit row and the metrics, which must
 * never cross the wire. Frameworks send `toPublicError(failure)`, never the
 * failure itself.
 *
 * Guide: Learn, "Enumeration".
 */
export type AuthErrorCode =
  /** Unknown email, wrong password, locked account, account refused by a hook: all the same. */
  | 'invalid_credentials'
  /** Unknown, expired, used or exhausted token or code. */
  | 'invalid_token'
  | 'invalid_email'
  /** The `ascii` email policy: the address has a non-ASCII character. */
  | 'email_not_ascii'
  /** Shorter than the policy's minimum. */
  | 'weak_password'
  | 'password_too_long'
  | 'breached_password'
  /** The signed-in account has no password to check (for example a social-only account). */
  | 'password_not_set'
  /** Only when the app opted into `registration.revealExisting`. */
  | 'email_in_use'
  /** Only with `throttle.lockout.revealLocked`: the account is locked (`retryAfterSeconds` when temporary). */
  | 'account_locked'
  | 'captcha_failed'
  /** The captcha provider could not answer: an outage, not the user's mistake. */
  | 'captcha_unavailable'
  | 'rate_limited'
  | 'session_expired'
  | 'fresh_auth_required'
  | 'second_factor_required'
  | 'invalid_second_factor'
  /** A hook refused for a reason that is safe to name only generically. */
  | 'forbidden'
  /** The membership plugin: an admin action aimed at the acting user. */
  | 'self_target'
  /** The membership plugin: the change would leave the scope without an admin. */
  | 'last_admin';

export interface AuthFailure {
  readonly ok: false;
  readonly code: AuthErrorCode;
  /** Internal cause for audit and metrics. Never send it to the client. */
  readonly reason: string;
  /** Set on `rate_limited`, and on a temporary `account_locked`: when the refusal ends. */
  readonly retryAfterSeconds?: number;
}

export interface AuthSuccess<T> {
  readonly ok: true;
  readonly value: T;
}

export type AuthResult<T> = AuthSuccess<T> | AuthFailure;

export function ok<T>(value: T): AuthSuccess<T>;
export function ok(): AuthSuccess<void>;

export function ok<T>(value?: T): AuthSuccess<T | undefined> {
  return { ok: true, value };
}

export function fail(
  code: AuthErrorCode,
  reason: string,
  extra?: { retryAfterSeconds?: number },
): AuthFailure {
  return extra?.retryAfterSeconds === undefined
    ? { ok: false, code, reason }
    : { ok: false, code, reason, retryAfterSeconds: extra.retryAfterSeconds };
}

/** The part of a failure that may be sent to the client. */
export function toPublicError(failure: AuthFailure): {
  code: AuthErrorCode;
  retryAfterSeconds?: number;
} {
  return failure.retryAfterSeconds === undefined
    ? { code: failure.code }
    : { code: failure.code, retryAfterSeconds: failure.retryAfterSeconds };
}

/**
 * Thrown only for programming and configuration errors (a missing store, an
 * invalid option), never for anything a user did.
 */
export class AuthConfigError extends Error {
  override readonly name = 'AuthConfigError';
}
