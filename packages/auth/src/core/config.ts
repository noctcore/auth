/**
 * Everything an app can change, with the default and the reason for it.
 * Where published guidance disagrees on a default, the stricter value wins.
 */
import type { BackgroundOptions } from './background';
import type { HookInput } from './hooks';
import type { PluginContext } from './plugin-context';
import type { RandomSource } from '../crypto/random';
import type { SessionCookieConfig } from '../http/cookie';
import type { BreachChecker } from '../password/breach';
import type { PasswordHasher } from '../password/hasher';
import type { PasswordPolicy } from '../password/policy';
import type { AuditSink } from '../ports/audit';
import type { CaptchaVerifier } from '../ports/captcha';
import type { Clock } from '../ports/clock';
import type { Logger, Metrics } from '../ports/logger';
import type { Mailer } from '../ports/mail';
import type { AuthUser, CounterStore, SessionStore, TokenStore, UserStore } from '../ports/stores';
import type { SessionOptions } from '../session/session-types';
import type { Duration } from '../shared/duration';
import type { EmailNormalizer, EmailPolicy } from '../shared/email';
import type { LockoutOptions, RateLimitRule } from '../throttle/rules';

/** Doors with their own rate limit. Keyed by client IP unless noted. */
export type Door =
  | 'login'
  | 'register'
  | 'password-reset-request'
  /** Per user: reset mails one account can receive. */
  | 'password-reset-mail'
  | 'password-reset'
  | 'password-reset-code'
  | 'email-verification'
  /** Per user: verification mails one account can request. */
  | 'email-verification-request'
  /** Per user. */
  | 'password-change'
  /** Per user: re-entering the password for a sensitive action. */
  | 'reauthenticate'
  /**
   * Per address: reset-code guesses for one email, known or not, from all IPs.
   * Trade-off: anyone who knows an address can spend this budget and block
   * that address's code-mode reset for 15 minutes. Link-mode reset (the
   * default) does not use this door and is unaffected.
   */
  | 'password-reset-code-address'
  /** Per user: email change requests one account can make. */
  | 'email-change-request'
  /**
   * Per address: email change requests naming one new address, from every
   * account. Keyed like the lockout, on a hash of the normalised address.
   */
  | 'email-change-address'
  /** Confirming an email change with a code or a link. */
  | 'email-change'
  /** Using a revert link. */
  | 'email-change-revert';

export const DEFAULT_DOOR_LIMITS: Readonly<Record<Door, RateLimitRule>> = {
  login: { limit: 10, window: '1m' },
  register: { limit: 10, window: '1m' },
  'password-reset-request': { limit: 10, window: '1m' },
  'password-reset-mail': { limit: 3, window: '1h' },
  'password-reset': { limit: 10, window: '1m' },
  'password-reset-code': { limit: 10, window: '1m' },
  'email-verification': { limit: 10, window: '1m' },
  'email-verification-request': { limit: 3, window: '1h' },
  'password-change': { limit: 5, window: '5m' },
  reauthenticate: { limit: 5, window: '5m' },
  'password-reset-code-address': { limit: 5, window: '15m' },
  'email-change-request': { limit: 3, window: '1h' },
  'email-change-address': { limit: 3, window: '1h' },
  'email-change': { limit: 10, window: '1m' },
  'email-change-revert': { limit: 10, window: '1m' },
};

export interface PasswordResetJob {
  readonly email: string;
  /** Server-minted; safe as a queue job id. Same for repeated requests for one address within a window. */
  readonly dedupeKey: string;
  /** The IP of the request that asked. */
  readonly ip: string;
  /** The user agent of the request that asked, when the framework passed one. Older jobs lack it. */
  readonly userAgent?: string;
}

/** A plugin: adds hooks and flows, never endpoints. `Id` becomes the namespace on the auth object. */
export interface AuthPlugin<Id extends string = string, F extends object = object> {
  readonly id: Id;
  // Plugins are written against any app's user and attribute types.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly hooks?: HookInput<any, any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly flows?: (context: PluginContext<any, any>) => F;
  /** Config the plugin cannot work without, checked by `createAuth`. */
  readonly requires?: ReadonlyArray<'captcha'>;
}

export interface AuthConfig<U extends AuthUser, A, P extends readonly AuthPlugin[]> {
  readonly stores: {
    readonly users: UserStore<U>;
    readonly sessions: SessionStore;
    readonly tokens: TokenStore;
    readonly counters: CounterStore;
  };
  readonly password: {
    readonly hasher: PasswordHasher;
    /** Default 12 to 256 characters. */
    readonly policy?: Partial<PasswordPolicy>;
    /** `pwnedPasswords()` recommended. False disables the check. Fails open either way. */
    readonly breachCheck?: BreachChecker | false;
  };
  readonly session?: SessionOptions<A> & {
    readonly cookie?: SessionCookieConfig;
    /** How recent a credential proof must be for sensitive actions. Default 10 min. */
    readonly freshAuthAge?: Duration;
    /**
     * Which session management doors ask for a credential proof inside
     * `freshAuthAge`. Both default to true. False skips only the age check:
     * the door still needs a live session of the same user, and every other
     * door (email change, two-factor management) still checks freshness.
     */
    readonly requireFreshAuth?: {
      /** Revoking another device's session with `sessions.revoke`. Default true. */
      readonly revokeSession?: boolean;
      /** Signing out every other device with `sessions.revokeOthers`. Default true. */
      readonly revokeOtherSessions?: boolean;
    };
  };
  /**
   * Server secret, at least 32 bytes. Separate keys are derived from it for
   * code HMACs, trusted-device tokens, session handles and plugins' keyed
   * hashes. Rotating it without `previousSecret` invalidates outstanding
   * codes, device cookies and two-factor recovery codes, never sessions, and
   * changes every session handle (`sessions.list`), so a client holding an
   * old handle must list again. Keep it apart from your CSRF secret.
   */
  readonly secret: Uint8Array | string;
  /**
   * The secret (or secrets, newest first) a rotation replaced, kept for a
   * grace window. Every key is derived from each of them too: a code, device
   * cookie, session handle or keyed hash made under one still verifies, while
   * everything new is signed and stored under `secret` only. Each must be at
   * least 32 bytes and differ from `secret` and from the others. Remove it
   * once the longest-lived value has expired: the trusted-device max age
   * (`throttle.lockout.deviceMaxAge`, 30 days by default), and only after users
   * holding two-factor recovery codes from before the rotation have made a
   * new set, since those never expire. Default none.
   */
  readonly previousSecret?: Uint8Array | string | readonly (Uint8Array | string)[];
  readonly email?: {
    /**
     * How an address is normalised before it is compared, stored or used as a
     * counter key, everywhere. Default `standard` (trim, lowercase A to Z,
     * refuse non-ASCII). `ascii` answers non-ASCII with `email_not_ascii`;
     * `unicode` keeps Unicode addresses (NFC, lowercased, single script per
     * part); or pass your own function, which must be pure and idempotent.
     * Changing it on a live database needs a data migration first: rows
     * normalised under the old policy no longer match.
     */
    readonly normalize?: EmailPolicy | EmailNormalizer;
  };
  readonly registration?: {
    /**
     * Answer `email_in_use` for a taken address instead of the uniform answer
     * plus an "account exists" mail. Default false (enumeration safe).
     */
    readonly revealExisting?: boolean;
    /**
     * Issue a session on registration. Only allowed with `revealExisting`, or the session would reveal the account is new.
     * Issuing it is work only a new address does, so it shows in sign-up timing; the answer already says the same.
     */
    readonly autoLogin?: boolean;
  };
  readonly emailVerification?: {
    /** Default `code`: 8 digits, the auth guide's preference, bound to the address it was sent to. */
    readonly kind?: 'code' | 'link';
    /** Default 15 min for codes, 24 h for links. */
    readonly ttl?: Duration;
    readonly digits?: number;
    readonly maxAttempts?: number;
    /**
     * Link verification only. Also accept a valid link opened without a
     * session, such as on another device or after the session expired. It
     * verifies the address and signs everyone out, but signs nobody in. A
     * session of another account is still refused. Default false: the link
     * counts only in a signed-in session of the same account.
     *
     * With it on, any request carrying the token verifies, so a mail scanner
     * that fetches the link can verify an account registered on someone
     * else's address. Put the token in the URL fragment and verify only on a
     * POST from a click, never on a GET or on page load.
     */
    readonly linkWithoutSession?: boolean;
  };
  readonly passwordReset?: {
    /** Default `link`. `code` sends digits that are exchanged for a short ticket. */
    readonly kind?: 'link' | 'code';
    /** Default 1 h for links, 15 min for codes. */
    readonly ttl?: Duration;
    readonly digits?: number;
    readonly maxAttempts?: number;
    /** Lifetime of the ticket a verified code becomes. Default 10 min. */
    readonly ticketTtl?: Duration;
    /**
     * Put the request on your queue; your worker calls `auth.jobs.processPasswordReset(job)`.
     * Without it the job runs detached in-process, which keeps the response
     * time independent of the address but is lost if the process dies.
     */
    readonly enqueue?: (job: PasswordResetJob) => Promise<void>;
    /** A completed reset proves the mailbox, so it marks the address verified. Default true. */
    readonly markEmailVerified?: boolean;
  };
  readonly emailChange?: {
    /** Default `code`: 8 digits typed by the signed-in user, bound to the account and the new address. */
    readonly kind?: 'code' | 'link';
    /** Default 15 min for codes, 1 h for links. */
    readonly ttl?: Duration;
    readonly digits?: number;
    readonly maxAttempts?: number;
    /** How long the revert link mailed to the old address works. Default 7 days, the minimum. */
    readonly revertTtl?: Duration;
    /** After a revert, how long the account may not change to the address it lost. Default 30 days. */
    readonly blockAfterRevert?: Duration;
  };
  readonly urls?: {
    /** Required for link verification. Put the token in the path or fragment and set `Referrer-Policy: no-referrer`. */
    readonly verifyEmail?: (token: string) => string;
    /** Required for link resets. */
    readonly resetPassword?: (token: string) => string;
    /** Required for link confirmation of an email change. */
    readonly confirmEmailChange?: (token: string) => string;
    /** Required to use the email change flows: the revert link mailed to the old address. */
    readonly revertEmailChange?: (token: string) => string;
  };
  readonly throttle?: {
    readonly lockout?: LockoutOptions;
    readonly doors?: Partial<Record<Door, RateLimitRule>>;
  };
  /** Checked on login, register and the reset request. Fails closed. */
  readonly captcha?: CaptchaVerifier;
  readonly mailer: Mailer;
  readonly audit?: AuditSink;
  readonly hooks?: HookInput<U, A>;
  readonly plugins?: P;
  readonly clock?: Clock;
  readonly random?: RandomSource;
  readonly logger?: Logger;
  readonly metrics?: Metrics;
  /**
   * Work the flows run off the response path (every mail, the lock notice, a
   * reset job without `enqueue`). Pass `waitUntil` on runtimes that freeze the
   * instance after the response, a `timeout` and `maxPending` to bound a
   * mailer that hangs. All optional; by default tasks run detached, with no
   * limit. Call `auth.flush()` on shutdown to wait for them.
   */
  readonly background?: BackgroundOptions;
}
