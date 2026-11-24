/**
 * The seams. Hooks let an app (tenancy, membership, portal accounts) and a
 * plugin (two-factor, invitations) add refusals and session attributes to the
 * core flows. A hook can only ADD a refusal or an attribute: no hook can skip a
 * core check, because the core runs its checks before and after the hooks
 * regardless of what they return.
 *
 * Plugins add flows (functions), never HTTP endpoints. The app's router calls
 * `auth.<pluginId>.<flow>(...)`.
 */
import type { AuthUser, StoredSession } from '../ports/stores';
import type { AuthErrorCode } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';

/** A hook's refusal. The `code` reaches the client; the `reason` only the audit row. */
export interface Refusal {
  readonly refuse: true;
  readonly code: AuthErrorCode;
  readonly reason: string;
}

/**
 * Refuse from a hook. On the login seam leave `code` at its default: a refusal
 * after a correct password (membership ended, account disabled) must read like
 * a wrong password to someone who does not hold the password.
 */
export function refuse(reason: string, code: AuthErrorCode = 'invalid_credentials'): Refusal {
  return { refuse: true, code, reason };
}

export type HookResult = void | undefined | Refusal;
type MaybePromise<T> = T | Promise<T>;

/** How a session came to be issued. Hooks can treat each path differently. */
export type IssueVia =
  | 'password'
  | 'register'
  | 'second-factor'
  | 'password-change'
  | 'email-verified'
  | 'email-changed'
  | 'revoke-others'
  | 'reauthenticate'
  | (string & {});

export type RevocationReason =
  | 'logout'
  | 'revoke-one'
  | 'revoke-others'
  | 'revoke-all'
  | 'password-reset'
  | 'password-change'
  | 'email-verified'
  | 'email-changed'
  | 'email-reverted'
  | 'evicted'
  /** The opt-in permanent lockout tier locked the account. */
  | 'locked-permanently'
  /** The two-factor plugin's sweep: a factor is required, the grace window is over and none is set up. */
  | 'two-factor-required'
  | (string & {});

/**
 * Where a session stands on the two-factor plugin's enforcement, on this
 * request. Computed live on every validation, never stored.
 */
export type TwoFactorStanding =
  /**
   * A factor is required and not set up yet, but the grace window is open:
   * the session works as usual. Remind the user before `graceEndsAt` (ms
   * since the epoch).
   */
  | { readonly state: 'grace'; readonly graceEndsAt: number }
  /**
   * A factor is required, none is set up and the grace window is over (or
   * the app's policy failed): the session may reach only the routes marked
   * for enrollment. Everything else answers `two_factor_enrollment_required`.
   */
  | { readonly state: 'enrollment-only' };

/** What `sessionStanding` hooks add to a validated session, for this request only. */
export interface SessionStanding {
  readonly twoFactor?: TwoFactorStanding;
}

/** A session `validateRequest` accepted, with its standing on this request. */
export type ValidatedSession<A> = StoredSession<A> & SessionStanding;

/** What a `passwordResetRequirements` hook says applying a reset will ask for. */
export interface PasswordResetRequirements {
  /** `resetPassword` will refuse without a `secondFactor` for this user. */
  readonly secondFactor?: boolean;
}

export interface AuthHooks<U extends AuthUser, A> {
  /** Attributes for a session being issued. On a re-issue `inherited` holds the old session's attributes. */
  sessionAttributes: (context: {
    user: U;
    via: IssueVia;
    inherited: A | undefined;
  }) => MaybePromise<Partial<A>>;
  /**
   * Last check before any session is minted, on every path. It also runs
   * after a correct password, before a second-factor challenge is handed out
   * (`via: 'password'`, `beforeChallenge: true`), so an account it refuses
   * gets `invalid_credentials` and never learns its password was right; the
   * session itself comes later (`via: 'second-factor'`), and this runs again.
   */
  beforeSessionCreate: (context: {
    user: U;
    via: IssueVia;
    attributes: A;
    meta: RequestMeta;
    /**
     * The live session this issue replaces, as the core read it from the
     * store for this user: set for the core's re-issues, and for an app's own
     * via whose `inherit` is a live session of this user (an issue whose
     * `inherit` is not is refused before the hooks, as `session_expired`).
     */
    reissueOf?: StoredSession<A>;
    /** Set when this runs before a second-factor challenge, not before a session. */
    beforeChallenge?: true;
  }) => MaybePromise<HookResult>;
  /** Runs on every validated request; a refusal revokes the session. Keep it cheap. */
  onSessionValidate: (context: {
    session: StoredSession<A>;
    meta: RequestMeta | undefined;
  }) => MaybePromise<HookResult>;
  /**
   * Runs on every validated request after `onSessionValidate` accepted the
   * session: a standing to attach to it for this request (the two-factor
   * plugin's grace or enrollment-only state). A standing never widens access:
   * an `enrollment-only` from any hook wins over a `grace`. Keep it cheap.
   */
  sessionStanding: (context: {
    session: StoredSession<A>;
    meta: RequestMeta | undefined;
  }) => MaybePromise<SessionStanding | undefined | void>;
  /**
   * After a correct password, before a session: return a challenge to finish
   * the login with a second factor instead. The first hook that returns one wins.
   */
  loginChallenge: (context: {
    user: U;
    rememberMe: boolean;
    epoch: number;
    meta: RequestMeta;
  }) => MaybePromise<{ challenge: string; methods: readonly string[] } | null | undefined>;
  /** Whether a reset may be sent to this account. A refusal is silent (the request answers the same). */
  beforePasswordResetRequest: (context: { user: U }) => MaybePromise<HookResult>;
  /**
   * What applying a reset of this account will ask for, or that it will be
   * refused, for a reset page that checks its link on load
   * (`inspectPasswordReset`). Answer `secondFactor: true` when your
   * `beforePasswordReset` hook will demand a code for this user (the
   * two-factor plugin does for a confirmed factor), and return the same
   * `refuse(...)` your `beforePasswordReset` would for an account it always
   * refuses (one your app closed), so the check answers what the reset
   * would. Any `true` wins; the first refusal answers the check. Read only:
   * spend nothing here.
   */
  passwordResetRequirements: (context: {
    user: U;
  }) => MaybePromise<PasswordResetRequirements | Refusal | undefined | void>;
  /** Before a reset is applied: a second-factor plugin demands its code here. */
  beforePasswordReset: (context: {
    user: U;
    secondFactor: string | undefined;
    meta: RequestMeta;
  }) => MaybePromise<HookResult>;
  /** Before a password change is applied, after the current password was checked. */
  beforePasswordChange: (context: {
    user: U;
    session: StoredSession<A>;
    secondFactor: string | undefined;
    meta: RequestMeta;
  }) => MaybePromise<HookResult>;
  /**
   * Before an email change is requested, after the fresh-auth check: a
   * second-factor plugin demands its step-up or code here. `newEmail` is the
   * normalised address asked for; refuse with a code that does not say whether
   * it is taken.
   */
  beforeEmailChange: (context: {
    user: U;
    session: StoredSession<A>;
    newEmail: string;
    secondFactor: string | undefined;
    meta: RequestMeta;
  }) => MaybePromise<HookResult>;
  /**
   * After a new account is created, before its verification mail. Awaited on
   * the response path and run only for a new address, so its duration shows in
   * sign-up timing against a taken address: keep it fast, and hand slow work
   * (a welcome mail, a CRM call) to your queue instead of awaiting it here.
   */
  afterRegister: (context: { user: U; meta: RequestMeta }) => MaybePromise<void>;
  /**
   * The opt-in permanent lockout tier just locked this account; it stays
   * locked until an admin calls `auth.lockout.clear`. Alert support or the
   * owner here. Runs off the response path, only for an address with an
   * account; errors are logged, never thrown into the flow.
   */
  onPermanentLock: (context: {
    userId: string;
    email: string;
    meta: RequestMeta;
  }) => MaybePromise<void>;
  /**
   * Sessions ended: close their sockets, drop caches. Errors are logged, never
   * thrown into the flow. Reason `evicted`: a new session pushed these past
   * `session.maxPerUser`; it fires once per issued session that evicted any,
   * with the ids that issue removed (`IssuedSession.evicted`, and their handles
   * as `IssuedSession.evictedHandles`).
   * Awaited on the response path (on sign-in when the cap evicts): keep it fast
   * and queue slow work.
   */
  onSessionsRevoked: (context: {
    userId: string;
    /** The internal store keys of the ended sessions. Server-side only: never send them to a client. */
    sessionIds: readonly string[];
    /**
     * The public handles of the same sessions, in the same order: what
     * `sessions.list` showed for them, so a client's list can drop them.
     */
    sessionHandles: readonly string[];
    reason: RevocationReason;
    /** The scope a scoped change concerns (a membership change in that scope); absent otherwise. */
    scope?: string;
  }) => MaybePromise<void>;
}

export type HookName = keyof AuthHooks<AuthUser, unknown>;

/** Each seam takes one hook or a list; lists run in order. */
export type HookInput<U extends AuthUser, A> = {
  readonly [K in keyof AuthHooks<U, A>]?: AuthHooks<U, A>[K] | ReadonlyArray<AuthHooks<U, A>[K]>;
};

export type HookLists<U extends AuthUser, A> = {
  readonly [K in keyof AuthHooks<U, A>]: ReadonlyArray<AuthHooks<U, A>[K]>;
};

const HOOK_NAMES: readonly HookName[] = [
  'sessionAttributes',
  'beforeSessionCreate',
  'onSessionValidate',
  'sessionStanding',
  'loginChallenge',
  'beforePasswordResetRequest',
  'passwordResetRequirements',
  'beforePasswordReset',
  'beforePasswordChange',
  'beforeEmailChange',
  'afterRegister',
  'onPermanentLock',
  'onSessionsRevoked',
];

/** Merges hook inputs in order (plugins first, then the app). */
export function mergeHooks<U extends AuthUser, A>(
  inputs: ReadonlyArray<HookInput<U, A> | undefined>,
): HookLists<U, A> {
  const lists: Record<string, unknown[]> = {};

  for (const name of HOOK_NAMES) lists[name] = [];

  for (const input of inputs) {
    if (!input) continue;

    for (const name of HOOK_NAMES) {
      const value = (input as Record<string, unknown>)[name];

      if (value === undefined) continue;

      const entries: readonly unknown[] = Array.isArray(value) ? (value as unknown[]) : [value];

      lists[name]?.push(...entries);
    }
  }

  return lists as unknown as HookLists<U, A>;
}

/** Runs refusal hooks in order and returns the first refusal. */
export async function firstRefusal<C>(
  hooks: ReadonlyArray<(context: C) => MaybePromise<HookResult>>,
  context: C,
): Promise<Refusal | null> {
  for (const hook of hooks) {
    const result = await hook(context);

    if (result && result.refuse === true) return result;
  }

  return null;
}
