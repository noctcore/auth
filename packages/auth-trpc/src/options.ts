/**
 * The adapter's settings, checked once when the context is created at boot,
 * so a weak CSRF secret, an empty origin allowlist or a nonsense hop count
 * stops the server before it listens instead of letting it run with a check
 * that quietly passes everything.
 */
import {
  AuthConfigError,
  resolveCsrfSettings,
  resolveSameSite,
  type CsrfSettings,
  type AuthEvent,
  type AuthResult,
  type AuthUser,
  type Clock,
  type Duration,
  type CookieSpec,
  type Hit,
  type RateLimitRule,
  type RequestMeta,
  type SessionCookieConfig,
  type StoredSession,
  type ValidatedSession,
  type TrustedHops,
  resolveClientIpHeader,
  resolveTrustedHops,
  toMilliseconds,
} from '@noctcore/auth';

/**
 * The part of a `createAuth` result the adapter uses. Any `createAuth(...)`
 * result fits, whatever its user type, session attributes or plugins.
 */
/**
 * `A` is the session attribute type of your `createAuth` call, inferred from
 * it, so `ctx.session` goes back into the flows without a cast.
 */
export interface TrpcAuth<U extends AuthUser = AuthUser, A = unknown> {
  readonly cookieName: string;
  readSessionToken(cookieHeader: string | null | undefined): string | null;
  readDeviceToken(cookieHeader: string | null | undefined): string | null;
  validateRequest(input: {
    token: string | null | undefined;
    meta?: RequestMeta;
    touch?: boolean;
  }): Promise<AuthResult<ValidatedSession<A>>>;
  requireFreshAuth(session: StoredSession<A>): AuthResult<void>;
  logout(input: { token: string | null | undefined; meta: RequestMeta }): Promise<{
    cookie: CookieSpec;
  }>;
  readonly context: {
    readonly users: { findById(id: string): Promise<U | null> };
    readonly clock: Clock;
    readonly throttle: { hit(scope: string, rule: RateLimitRule): Promise<Hit> };
    /**
     * An HMAC of `message` under a key derived from the server secret for
     * `purpose`. Names the user in a `keyBy: 'user'` rate limit key.
     */
    keyedHash(purpose: string, message: string): string;
    readonly logger: {
      error(message: string, context?: Record<string, unknown>): void;
    };
    emit(event: AuthEvent, meta: RequestMeta | undefined): Promise<void>;
    /**
     * The session cookie config. The CSRF, pre-session and blank session
     * cookies take their `SameSite` from it, per request `Origin`, exactly as
     * the session cookie does. Missing (a hand-made stand-in): `Lax`.
     */
    readonly cookie?: SessionCookieConfig;
  };
}

export interface CsrfOptions {
  /**
   * Signs the double-submit token. At least 32 bytes each, and not the auth
   * secret. Current secret first, previous ones after it during a rollover: a
   * safe request replaces a token signed by a previous secret with one under
   * the current secret.
   */
  readonly secrets: readonly (string | Uint8Array)[];
  /** Origins allowed to send mutations, such as `https://app.example`. */
  readonly allowedOrigins: readonly string[];
  /** Accept `Sec-Fetch-Site: same-site` too, for sibling subdomains you trust. Default false. */
  readonly allowSameSite?: boolean;
  /**
   * Exact origins allowed to send mutations from another site, such as a
   * desktop shell on its own scheme (`app://desktop`). An origin listed here
   * counts as allowed, and its `Sec-Fetch-Site: cross-site` requests pass;
   * the double-submit token is still required. Matched exactly, no
   * wildcards. Trust each one as much as your own origin. Default none.
   */
  readonly crossSiteOrigins?: readonly string[];
  /** Header the page echoes the token in. Default `x-csrf-token`. */
  readonly headerName?: string;
}

export interface AuthContextOptions<U extends AuthUser = AuthUser, A = unknown> {
  /** The `createAuth(...)` result. */
  readonly auth: TrpcAuth<U, A>;
  /**
   * How many reverse proxies sit in front of the server, counted from the
   * right of `X-Forwarded-For` (the core's `clientIp` rule), 0 when none; or
   * a list of proxy addresses, CIDR ranges and the presets `loopback`,
   * `linklocal` and `uniquelocal`, trusted by the socket address.
   */
  readonly trustedHops: TrustedHops;
  /**
   * A single-address header your edge sets, such as `cf-connecting-ip`.
   * Needs `trustedHops` as a list naming the edge (or hops that accept
   * traffic only from it); read only when the socket address is inside that
   * list and the value is exactly one IP, otherwise `X-Forwarded-For`
   * decides. Off by default.
   */
  readonly clientIpHeader?: string;
  readonly csrf: CsrfOptions;
  /**
   * The user's roles, for `role(...)`. Called on every call that needs a
   * role, with the user just loaded from the store, so a role change takes
   * effect on the next request.
   */
  readonly roles?: (user: U) => readonly string[] | Promise<readonly string[]>;
  /**
   * Whether a request counts as activity for the session's idle timeout.
   * `true` (the default) refreshes the session's last-active time, at most
   * once per `touchInterval`, on every request. A predicate is asked about
   * each procedure path of the request (`notifications.count`), before the
   * session is validated: return false for procedures the page calls on its
   * own (a poll on a timer, a status check), so an idle session still
   * expires while only they are called. A procedure whose meta says
   * `touch: false` is passive too. A batch touches when any of its
   * procedures is active. `false` touches on no request. A passive request
   * is still answered with its session, and the CSRF verdict and the
   * guarded procedures' decisions do not change.
   */
  readonly touch?: boolean | ((path: string) => boolean);
  /**
   * How long a subscription behind a session check (`authed`, `freshAuth`,
   * `role`, `protectedProcedure`, the nestjs-trpc guard) may go on sending
   * events on the session it opened with. tRPC builds the context once per
   * HTTP request, and an SSE subscription is one request that stays open, so
   * its session is validated once. Before an event leaves, when the last
   * check is older than this, the session is validated again (without
   * counting as activity) and its user loaded; when either is gone, or the
   * session became enrollment-only, the stream ends with `session_expired`
   * (or `two_factor_enrollment_required`) instead of the event. `0` checks
   * before every event. `false` turns it off. Default `30s`.
   */
  readonly revalidateSubscriptions?: Duration | false;
}

/** The options after the boot checks, with secrets as bytes and cookie names fixed. */
export interface ResolvedOptions {
  readonly auth: TrpcAuth;
  readonly trustedHops: TrustedHops;
  readonly clientIpHeader: string | undefined;
  readonly roles: ((user: AuthUser) => readonly string[] | Promise<readonly string[]>) | undefined;
  readonly secure: boolean;
  /** The session cookie config the adapter's cookies take their `SameSite` from. */
  readonly cookie: SessionCookieConfig;
  /** False when no procedure touches; otherwise whether the procedure at a path does. */
  readonly touch: false | ((path: string) => boolean);
  readonly csrf: CsrfSettings;
  /** Milliseconds a subscription's session check stays good for, or false when off. */
  readonly revalidateEvery: number | false;
}

/**
 * More proxies than any real deployment chains. A count above it is a typo
 * or a unit mistake, and a large count trusts client-written hops.
 */
export const MAX_TRUSTED_HOPS = 16;

export function resolveOptions<U extends AuthUser, A>(
  options: AuthContextOptions<U, A>,
): ResolvedOptions {
  const { auth, csrf, trustedHops } = options;

  if (!auth || typeof auth.validateRequest !== 'function') {
    throw new AuthConfigError('createAuthContext needs the createAuth(...) result as `auth`');
  }

  // Called on every request that needs a role: anything else would throw there instead of here.
  if (options.roles !== undefined && options.roles !== null && typeof options.roles !== 'function')
    throw new AuthConfigError('roles must be a function of the user');

  const hops = resolveTrustedHops(trustedHops, MAX_TRUSTED_HOPS);
  const clientIpHeader = resolveClientIpHeader(options.clientIpHeader, hops);
  // The session cookie is `__Host-` prefixed exactly when it is Secure, and
  // the CSRF cookies follow it, so one setting decides all three.
  const secure = auth.cookieName.startsWith('__Host-');
  const resolvedCsrf = resolveCsrfSettings(csrf, secure);

  const touch = resolveTouch(options.touch);
  // The adapter's cookies are Secure exactly when the session cookie is, so
  // SameSite resolves against that, never against a config that disagrees:
  // `None` without Secure is refused here for a fixed value, and by
  // `resolveSameSite` (before any cookie is built) for a function.
  const cookie: SessionCookieConfig = { ...auth.context.cookie, secure };

  if (typeof cookie.sameSite !== 'function') resolveSameSite(cookie, undefined);

  return {
    auth: auth,
    trustedHops: hops,
    clientIpHeader,
    roles: options.roles as ResolvedOptions['roles'],
    secure,
    cookie,
    touch,
    csrf: resolvedCsrf,
    revalidateEvery: resolveRevalidateEvery(options.revalidateSubscriptions),
  };
}

/** The default bound on how long an open subscription keeps a revoked session. */
export const DEFAULT_REVALIDATE_SUBSCRIPTIONS: Duration = '30s';

/** The `revalidateSubscriptions` option resolved; a bad duration stops the boot. */
function resolveRevalidateEvery(
  every: AuthContextOptions['revalidateSubscriptions'],
): ResolvedOptions['revalidateEvery'] {
  if (every === false) return false;

  try {
    return toMilliseconds(every ?? DEFAULT_REVALIDATE_SUBSCRIPTIONS);
  } catch {
    throw new AuthConfigError(
      'revalidateSubscriptions must be a duration (such as 30s, or 0 to check before every ' +
        'event) or false',
    );
  }
}

/** The `touch` option resolved; anything but a boolean or a function stops the boot. */
function resolveTouch(touch: AuthContextOptions['touch']): ResolvedOptions['touch'] {
  if (touch === undefined || touch === true) return () => true;
  if (touch === false) return false;
  if (typeof touch === 'function') return (path) => touch(path) !== false;

  throw new AuthConfigError('touch must be a boolean or a function of the procedure path');
}
