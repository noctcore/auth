/**
 * The module's settings, checked once at boot so a weak CSRF secret, an empty
 * origin allowlist or a nonsense hop count stops the app before it listens
 * instead of letting it run with a check that quietly passes everything.
 */
import type { IncomingHttpHeaders } from 'node:http';
import {
  AuthConfigError,
  resolveCsrfSettings,
  resolveSameSite,
  type AuthResult,
  type AuthUser,
  type Clock,
  type CookieSpec,
  type Duration,
  type RequestMeta,
  type SessionCookieConfig,
  type StoredSession,
  type TrustedHops,
  type ValidatedSession,
  resolveClientIpHeader,
  resolveTrustedHops,
  toMilliseconds,
} from '@noctcore/auth';

/**
 * The part of a `createAuth` result the module uses. Any `createAuth(...)`
 * result fits, whatever its user type, session attributes or plugins.
 */
export interface NestAuth<U extends AuthUser = AuthUser> {
  readonly cookieName: string;
  readSessionToken(cookieHeader: string | null | undefined): string | null;
  validateRequest(input: {
    token: string | null | undefined;
    meta?: RequestMeta;
    touch?: boolean;
  }): Promise<AuthResult<ValidatedSession<unknown>>>;
  requireFreshAuth(session: StoredSession<unknown>): AuthResult<void>;
  /** Waits for background work (mail sends); the module calls it on shutdown, bounded. */
  flush?(options?: { readonly timeout?: Duration }): Promise<void>;
  logout(input: { token: string | null | undefined; meta: RequestMeta }): Promise<{
    cookie: CookieSpec;
  }>;
  readonly context: {
    readonly users: { findById(id: string): Promise<U | null> };
    readonly clock: Clock;
    readonly logger: {
      error(message: string, context?: Record<string, unknown>): void;
    };
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
  /** Origins allowed to send unsafe requests, such as `https://app.example`. */
  readonly allowedOrigins: readonly string[];
  /** Accept `Sec-Fetch-Site: same-site` too, for sibling subdomains you trust. Default false. */
  readonly allowSameSite?: boolean;
  /**
   * Exact origins allowed to send unsafe requests from another site, such
   * as a desktop shell on its own scheme (`app://desktop`). An origin listed
   * here counts as allowed, and its `Sec-Fetch-Site: cross-site` requests
   * pass; the double-submit token is still required. Matched exactly, no
   * wildcards. Trust each one as much as your own origin. Default none.
   */
  readonly crossSiteOrigins?: readonly string[];
  /**
   * Paths that skip CSRF entirely, such as a webhook that authenticates with
   * a signature. A string matches the request path exactly (a global prefix
   * included); a RegExp is tested against it. Exempt requests are still
   * subject to the session guard.
   */
  readonly exempt?: readonly (string | RegExp)[];
  /** Header the page echoes the token in. Default `x-csrf-token`. */
  readonly headerName?: string;
}

/** What a `touch` predicate sees of a request. */
export interface TouchRequest {
  /** `GET`, `POST`, ... as the client sent it. */
  readonly method: string;
  /** The request path, a global prefix included, without the query string. */
  readonly path: string;
  readonly headers: IncomingHttpHeaders;
}

export interface AuthModuleOptions<U extends AuthUser = AuthUser> {
  /** The `createAuth(...)` result. */
  readonly auth: NestAuth<U>;
  /**
   * How many reverse proxies sit in front of the app, counted from the right
   * of `X-Forwarded-For` (see `trustedHopsFromEnv`), 0 when none; or a list
   * of proxy addresses, CIDR ranges and the presets `loopback`, `linklocal`
   * and `uniquelocal`, trusted by the socket address.
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
   * The user's roles, for `@RequireRole()`. Called on every request that
   * needs a role, with the user just loaded from the store, so a role change
   * takes effect on the next request.
   */
  readonly roles?: (user: U) => readonly string[] | Promise<readonly string[]>;
  /**
   * How long shutdown waits for background work (mail sends) before it gives
   * up, logs what it left running and lets the app close. Default `'10s'`.
   */
  readonly shutdownTimeout?: Duration;
  /**
   * Whether a request counts as activity for the session's idle timeout.
   * `true` (the default) refreshes the session's last-active time, at most
   * once per `touchInterval`, on every request. A predicate decides per
   * request, before the session is validated: return false for traffic the
   * page makes on its own (a poll on a timer, a status check), so an idle
   * session still expires while only such requests arrive. `false` touches
   * on no request. A passive request is still answered with its session,
   * and the CSRF checks and the guard's decisions do not change.
   */
  readonly touch?: boolean | ((request: TouchRequest) => boolean);
}

/** How long shutdown waits for background work by default. */
export const DEFAULT_SHUTDOWN_TIMEOUT: Duration = '10s';

/** The options after the boot checks, with secrets as bytes and cookie names fixed. */
export interface ResolvedOptions {
  readonly auth: NestAuth;
  readonly trustedHops: TrustedHops;
  readonly clientIpHeader: string | undefined;
  readonly roles: ((user: AuthUser) => readonly string[] | Promise<readonly string[]>) | undefined;
  readonly secure: boolean;
  /** The session cookie config the adapter's cookies take their `SameSite` from. */
  readonly cookie: SessionCookieConfig;
  readonly shutdownTimeout: Duration;
  /** Whether this request refreshes the session's last-active time. */
  readonly touch: (request: TouchRequest) => boolean;
  readonly csrf: {
    readonly secrets: readonly Uint8Array[];
    /** `allowedOrigins` and `crossSiteOrigins` together: every origin the Origin check accepts. */
    readonly allowedOrigins: readonly string[];
    readonly crossSiteOrigins: readonly string[];
    readonly allowSameSite: boolean;
    readonly exempt: readonly (string | RegExp)[];
    readonly headerName: string;
    readonly cookieName: string;
    readonly preSessionCookieName: string;
  };
}

/**
 * The most proxy hops the module will trust. Real deployments run one to three
 * (a CDN, a load balancer, an ingress); a larger number is far more likely a
 * typo than a chain, and would trust entries a client wrote.
 */
export const MAX_TRUSTED_HOPS = 16;

export function resolveOptions<U extends AuthUser>(options: AuthModuleOptions<U>): ResolvedOptions {
  const { auth, csrf, trustedHops } = options;

  if (!auth || typeof auth.validateRequest !== 'function') {
    throw new AuthConfigError('AuthModule needs the createAuth(...) result as `auth`');
  }

  const hops = resolveTrustedHops(trustedHops, MAX_TRUSTED_HOPS);
  const clientIpHeader = resolveClientIpHeader(options.clientIpHeader, hops);
  // The session cookie is `__Host-` prefixed exactly when it is Secure, and
  // the CSRF cookies follow it, so one setting decides all three.
  const secure = auth.cookieName.startsWith('__Host-');
  const resolvedCsrf = resolveCsrfSettings(csrf, secure);
  const exempt: unknown = csrf.exempt ?? [];

  // A rule that is neither would throw on every unsafe request instead of at boot.
  if (
    !Array.isArray(exempt) ||
    exempt.some((rule) => typeof rule !== 'string' && !(rule instanceof RegExp))
  ) {
    throw new AuthConfigError('csrf.exempt must be a list of paths and RegExps');
  }

  const shutdownTimeout = options.shutdownTimeout ?? DEFAULT_SHUTDOWN_TIMEOUT;

  if (!(shutdownMilliseconds(shutdownTimeout) > 0))
    throw new AuthConfigError('shutdownTimeout must be a duration longer than zero');

  const touch = resolveTouch(options.touch);
  // The adapter's cookies are Secure exactly when the session cookie is, so
  // SameSite resolves against that, never against a config that disagrees:
  // `None` without Secure is refused here for a fixed value, and by
  // `resolveSameSite` (before any cookie is built) for a function.
  const cookie: SessionCookieConfig = { ...auth.context.cookie, secure };

  if (typeof cookie.sameSite !== 'function') resolveSameSite(cookie, undefined);

  return {
    auth,
    trustedHops: hops,
    clientIpHeader,
    roles: options.roles as ResolvedOptions['roles'],
    secure,
    cookie,
    shutdownTimeout,
    touch,
    csrf: { ...resolvedCsrf, exempt: [...(exempt as readonly (string | RegExp)[])] },
  };
}

/** The `touch` option as a predicate; anything but a boolean or a function stops the boot. */
function resolveTouch(touch: AuthModuleOptions['touch']): (request: TouchRequest) => boolean {
  if (touch === undefined || touch === true) return () => true;
  if (touch === false) return () => false;
  if (typeof touch === 'function') return (request) => touch(request) !== false;

  throw new AuthConfigError('touch must be a boolean or a function of the request');
}

/** The shutdown bound in milliseconds, or `NaN` when it is not a duration. */
function shutdownMilliseconds(timeout: Duration): number {
  try {
    return toMilliseconds(timeout);
  } catch {
    return Number.NaN;
  }
}
