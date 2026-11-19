/**
 * The adapter's settings, checked once when the context is created at boot,
 * so a weak CSRF secret, an empty origin allowlist or a nonsense hop count
 * stops the server before it listens instead of letting it run with a check
 * that quietly passes everything.
 */
import {
  assertExactOrigins,
  AuthConfigError,
  createCsrfToken,
  resolveSameSite,
  type AuthEvent,
  type AuthResult,
  type AuthUser,
  type Clock,
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
   * secret. Current secret first, previous ones after it during a rollover.
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
  readonly csrf: {
    readonly secrets: readonly Uint8Array[];
    /** `allowedOrigins` and `crossSiteOrigins` together: every origin the Origin check accepts. */
    readonly allowedOrigins: readonly string[];
    readonly crossSiteOrigins: readonly string[];
    readonly allowSameSite: boolean;
    readonly headerName: string;
    readonly cookieName: string;
    readonly preSessionCookieName: string;
  };
}

const HEADER = /^[a-z0-9-]+$/u;

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

  const hops = resolveTrustedHops(trustedHops, MAX_TRUSTED_HOPS);
  const clientIpHeader = resolveClientIpHeader(options.clientIpHeader, hops);

  if (csrf.secrets.length === 0)
    throw new AuthConfigError('csrf.secrets needs at least one secret');

  const crossSiteOrigins = assertExactOrigins(csrf.crossSiteOrigins ?? [], 'csrf.crossSiteOrigins');

  if (csrf.allowedOrigins.length === 0 && crossSiteOrigins.length === 0)
    throw new AuthConfigError('csrf.allowedOrigins is empty');

  const secrets = csrf.secrets.map((secret) =>
    typeof secret === 'string' ? new TextEncoder().encode(secret) : secret,
  );

  // The core refuses a short secret when it signs; signing once here moves
  // that refusal to boot.
  for (const secret of secrets) createCsrfToken(secret, 'boot-check');

  const headerName = (csrf.headerName ?? 'x-csrf-token').toLowerCase();

  if (!HEADER.test(headerName))
    throw new AuthConfigError(`Invalid CSRF header name: ${headerName}`);

  // The session cookie is `__Host-` prefixed exactly when it is Secure, and
  // the CSRF cookies follow it, so one setting decides all three.
  const secure = auth.cookieName.startsWith('__Host-');
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
    csrf: {
      secrets,
      allowedOrigins: [...csrf.allowedOrigins, ...crossSiteOrigins],
      crossSiteOrigins,
      allowSameSite: csrf.allowSameSite ?? false,
      headerName,
      cookieName: secure ? '__Host-csrf' : 'csrf',
      preSessionCookieName: secure ? '__Host-presession' : 'presession',
    },
  };
}
