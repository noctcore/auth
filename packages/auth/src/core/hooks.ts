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
  | (string & {});

export interface AuthHooks<U extends AuthUser, A> {
  /** Attributes for a session being issued. On a re-issue `inherited` holds the old session's attributes. */
  sessionAttributes: (context: {
    user: U;
    via: IssueVia;
    inherited: A | undefined;
  }) => MaybePromise<Partial<A>>;
  /** Last check before any session is minted, on every path. */
  beforeSessionCreate: (context: {
    user: U;
    via: IssueVia;
    attributes: A;
    meta: RequestMeta;
  }) => MaybePromise<HookResult>;
  /** Runs on every validated request; a refusal revokes the session. Keep it cheap. */
  onSessionValidate: (context: {
    session: StoredSession<A>;
    meta: RequestMeta | undefined;
  }) => MaybePromise<HookResult>;
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
   * After an email change was reverted (or its revert was refused because the
   * old address has an account again, with the account locked out anyway),
   * once the password is removed and every session revoked. `changedAt` is
   * when the change was confirmed: a second-factor plugin removes a factor
   * enrolled since then. Awaited, and an error fails the revert with the link
   * still unspent, so the owner can click it again.
   */
  onEmailReverted: (context: {
    userId: string;
    changedAt: number;
    meta: RequestMeta;
  }) => MaybePromise<void>;
  /** Sessions ended: close their sockets, drop caches. Errors are logged, never thrown into the flow. */
  onSessionsRevoked: (context: {
    userId: string;
    sessionIds: readonly string[];
    reason: RevocationReason;
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
  'loginChallenge',
  'beforePasswordResetRequest',
  'beforePasswordReset',
  'beforePasswordChange',
  'beforeEmailChange',
  'afterRegister',
  'onEmailReverted',
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
