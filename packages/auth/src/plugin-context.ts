/**
 * What flows and plugins are given: the stores, the managers and the shared
 * steps (rate limit, captcha, audit, mail, issuing a session), so a plugin
 * flow goes through the same checks as a core flow. In particular every
 * session is minted by `issueSession`, the one seam, so no plugin can mint a
 * session that skips the hooks, the epoch fence or the attribute schema.
 */
import type { AuthEvent } from './audit';
import type { CaptchaDoor } from './captcha';
import type { Clock } from './clock';
import type { CookieSpec } from './cookie';
import type { Door } from './config';
import type { AuthFailure, AuthResult } from './errors';
import type { HookLists, IssueVia, RevocationReason } from './hooks';
import type { Logger, Metrics } from './logger';
import type { AuthMailEvent } from './mail';
import type { RequestMeta } from './meta';
import type { PasswordHasher } from './password/hasher';
import type { PasswordPolicy } from './password/policy';
import type { RandomSource } from './random';
import type { SessionManager } from './session';
import type { AuthUser, StoredSession, UserStore } from './stores';
import type { Throttle } from './throttle';
import type { OneTimeTokens } from './tokens';

/** A session just issued: the token for the cookie, the stored record, and the cookie itself. */
export interface IssuedSession<A> {
  readonly token: string;
  readonly session: StoredSession<A>;
  readonly cookie: CookieSpec;
  /** The trusted-device cookie: set it with the session cookie. Voided by a password change, reset or revoke-all. */
  readonly deviceCookie: CookieSpec;
}

export interface IssueOptions<A> {
  readonly via: IssueVia;
  readonly meta: RequestMeta;
  readonly rememberMe?: boolean;
  /** Keep the cookie past the browser session even without remember-me. Default: same as rememberMe. */
  readonly persistentCookie?: boolean;
  /** The epoch read before the credential was checked. */
  readonly epoch?: number;
  /** The session this one replaces: its attributes, remember-me and cookie shape carry over. */
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
  /** Emits an audit event (and counts it). Never throws. */
  emit(event: AuthEvent, meta: RequestMeta | undefined): Promise<void>;
  /** Hands a mail event to the mailer with a fresh dedupe key. Errors are logged, never thrown. */
  mail(event: DistributiveOmit<AuthMailEvent, 'dedupeKey'>): Promise<void>;
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
  /** Revokes every session of the user and tells the hooks. */
  revokeAllSessions(userId: string, reason: RevocationReason): Promise<void>;
  /** Tells the hooks sessions ended. Never throws. */
  notifyRevoked(
    userId: string,
    sessionIds: readonly string[],
    reason: RevocationReason,
  ): Promise<void>;
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
