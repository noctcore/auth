/**
 * What flows and plugins are given: the stores, the managers and the shared
 * steps (rate limit, captcha, audit, mail, issuing a session), so a plugin
 * flow goes through the same checks as a core flow. In particular every
 * session is minted by `issueSession`, the one seam, so no plugin can mint a
 * session that skips the hooks, the epoch fence or the attribute schema.
 */
import type { Door } from './config';
import type { HookLists, IssueVia, RevocationReason } from './hooks';
import type { RandomSource } from '../crypto/random';
import type { CookieSpec, SessionCookieConfig } from '../http/cookie';
import type { PasswordHasher } from '../password/hasher';
import type { PasswordPolicy } from '../password/policy';
import type { AuthEvent } from '../ports/audit';
import type { CaptchaDoor } from '../ports/captcha';
import type { Clock } from '../ports/clock';
import type { Logger, Metrics } from '../ports/logger';
import type { AuthMailEvent } from '../ports/mail';
import type { AuthUser, StoredSession, UserStore, WithPasswordHash } from '../ports/stores';
import type { SessionManager } from '../session/session-manager';
import type { NormalizedEmail } from '../shared/email';
import type { AuthFailure, AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import type { Throttle } from '../throttle/throttle';
import type { OneTimeTokens } from '../tokens/one-time-tokens';

/** A session just issued: the token for the cookie, the stored record, and the cookie itself. */
export interface IssuedSession<A> {
  readonly token: string;
  readonly session: StoredSession<A>;
  readonly cookie: CookieSpec;
  /** The trusted-device cookie: set it with the session cookie. Voided by a password change, reset or revoke-all. */
  readonly deviceCookie: CookieSpec;
  /**
   * Store keys of the user's older sessions deleted to keep within
   * `session.maxPerUser`, oldest first; empty when none were. Server-side
   * only, like `session.id`: never send them to a client. The same ids reach
   * `onSessionsRevoked` as `sessionIds`, with reason `evicted`.
   */
  readonly evicted: readonly string[];
  /**
   * The public handles of the `evicted` sessions, in the same order: the
   * names `sessions.list` showed and `onSessionsRevoked` passes as
   * `sessionHandles`. Safe to send to a client.
   */
  readonly evictedHandles: readonly string[];
}

export interface IssueOptions<A> {
  readonly via: IssueVia;
  readonly meta: RequestMeta;
  readonly rememberMe?: boolean;
  /** Keep the cookie past the browser session even without remember-me. Default: same as rememberMe. */
  readonly persistentCookie?: boolean;
  /** The epoch read before the credential was checked. */
  readonly epoch?: number;
  /**
   * The session this one replaces: its attributes, remember-me and cookie
   * shape carry over. The re-issue vias (`password-change`, `reauthenticate`,
   * `revoke-others`, `email-verified`, `email-changed`) are for the core's own flows: they
   * require an `inherit` the core itself read live from the store, for the
   * same user, before the flow revoked anything, and refuse every other value.
   */
  readonly inherit?: StoredSession<A>;
  /** When the credential was proved. Default now; a re-issue that proved nothing passes the old value. */
  readonly authenticatedAt?: number;
}

/** Session reads and revocations. Deliberately without `mint`: sessions are only created by `issueSession`. */
export type SessionAccess<A> = Pick<
  SessionManager<A>,
  | 'absoluteTtlMs'
  | 'rememberMeTtlMs'
  | 'readEpoch'
  | 'validate'
  | 'findActive'
  | 'listActive'
  | 'revoke'
  | 'revokeToken'
  | 'revokeAll'
>;

export interface PluginContext<U extends AuthUser, A> {
  readonly users: UserStore<U>;
  readonly sessions: SessionAccess<A>;
  readonly tokens: OneTimeTokens;
  readonly throttle: Throttle;
  readonly hasher: PasswordHasher;
  readonly policy: PasswordPolicy;
  readonly hooks: HookLists<U, A>;
  readonly clock: Clock;
  readonly random: RandomSource;
  readonly logger: Logger;
  readonly metrics: Metrics;
  /** The session cookie config, so a plugin's own cookies get the same Secure, prefix and SameSite. */
  readonly cookie: SessionCookieConfig;
  /**
   * HMAC-SHA-256 (lowercase hex) of `message` under a key derived from the
   * server secret for `purpose`. For storing short secrets (recovery codes)
   * so that a leaked table cannot be searched offline. The key never leaves
   * the core; two purposes never share one.
   */
  keyedHash(purpose: string, message: string): string;
  /**
   * The public handle of the session stored under `sessionId`: an HMAC of the
   * store key under a key derived from the server secret, as unpadded
   * base64url. `sessions.list` shows it, `sessions.revoke` takes it and
   * `onSessionsRevoked` passes it as `sessionHandles`, so a client never sees
   * a store key. Stable while the server secret is; rotating the secret
   * changes every handle (never a session).
   */
  sessionHandle(sessionId: string): string;
  /**
   * The address in the one spelling the configured `email.normalize` policy
   * gives, or null when the policy refuses it. Every comparison of two
   * addresses, every address written to a store and every counter key derived
   * from one goes through this, never through a fixed function.
   */
  normalizeEmail(input: unknown): NormalizedEmail | null;
  /**
   * `normalizeEmail` for input from a request: the refusal carries the public
   * code (`invalid_email`, or `email_not_ascii` under the `ascii` policy).
   */
  parseEmail(input: unknown): AuthResult<NormalizedEmail>;
  /**
   * `users.findCredentialByEmail`, but a row whose stored `email` is not
   * exactly `email` counts as not found. A store whose lookup goes through a
   * case- or accent-insensitive collation would otherwise hand one account to
   * several spellings, each with its own lockout and rate-limit keys. Every
   * lookup by address goes through this.
   */
  findCredentialByEmail(email: NormalizedEmail): Promise<WithPasswordHash<U> | null>;
  /** Refuses (`fresh_auth_required`) when the session's last credential proof is older than `session.freshAuthAge`. */
  requireFreshAuth(session: StoredSession<A>): AuthResult<void>;
  /**
   * Re-reads the session from the store and checks freshness on that live copy,
   * not on the object passed in: `session_expired` unless it is live (unexpired,
   * not idle, current epoch) and still the same user's, then `fresh_auth_required`
   * as `requireFreshAuth`. Returns the live copy. Use it at every door that
   * needs fresh authentication, so a hand-built or stale object cannot claim it.
   */
  requireFreshLiveSession(session: StoredSession<A>): Promise<AuthResult<StoredSession<A>>>;
  /** Emits an audit event (and counts it). Never throws. */
  emit(event: AuthEvent, meta: RequestMeta | undefined): Promise<void>;
  /**
   * Hands a mail event to the mailer with a fresh dedupe key without awaiting
   * delivery. `mailer.send` is called before this returns, so whatever `send`
   * does before it returns its promise (building a template, say) is still on
   * the response path; only the settling of that promise is not awaited, so a
   * slow or hung delivery does not hold up the answer. At most once: a failure
   * is logged, never thrown and never retried; retries belong to the app's
   * mailer or queue. No timeout: a `send` that never settles stays pending.
   */
  mail(event: DistributiveOmit<AuthMailEvent, 'dedupeKey'>): void;
  /** One hit on a door's window; a failure result when over the limit. */
  rateLimit(door: Door, key: string, meta: RequestMeta | undefined): Promise<AuthFailure | null>;
  /** Verifies the captcha when one is configured; a failure result when it does not pass. */
  checkCaptcha(
    door: CaptchaDoor,
    token: string | undefined,
    meta: RequestMeta,
  ): Promise<AuthFailure | null>;
  /** Verifies a password against a stored hash, paying a full verify even when there is none. */
  verifyPassword(passwordHash: string | null | undefined, password: string): Promise<boolean>;
  /** Policy, breach check and hash for a NEW password. */
  hashNewPassword(password: string, meta: RequestMeta | undefined): Promise<AuthResult<string>>;
  /** THE seam: every session is minted here. */
  issueSession(user: U, options: IssueOptions<A>): Promise<AuthResult<IssuedSession<A>>>;
  /**
   * Revokes every session of the user and tells the hooks. `scope` names the
   * scope a scoped change concerns (a membership change), passed on to
   * `onSessionsRevoked`; the revocation itself always covers every scope.
   */
  revokeAllSessions(
    userId: string,
    reason: RevocationReason,
    options?: { scope?: string },
  ): Promise<void>;
  /** Tells the hooks sessions ended. Never throws. */
  notifyRevoked(
    userId: string,
    sessionIds: readonly string[],
    reason: RevocationReason,
    options?: { scope?: string },
  ): Promise<void>;
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
