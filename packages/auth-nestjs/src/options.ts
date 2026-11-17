/**
 * The module's settings, checked once at boot so a weak CSRF secret, an empty
 * origin allowlist or a nonsense hop count stops the app before it listens
 * instead of letting it run with a check that quietly passes everything.
 */
import {
  AuthConfigError,
  createCsrfToken,
  type AuthResult,
  type AuthUser,
  type Clock,
  type CookieSpec,
  type Duration,
  type RequestMeta,
  type StoredSession,
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
  }): Promise<AuthResult<StoredSession<unknown>>>;
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
  };
}

export interface CsrfOptions {
  /**
   * Signs the double-submit token. At least 32 bytes each, and not the auth
   * secret. Current secret first, previous ones after it during a rollover.
   */
  readonly secrets: readonly (string | Uint8Array)[];
  /** Origins allowed to send unsafe requests, such as `https://app.example`. */
  readonly allowedOrigins: readonly string[];
  /** Accept `Sec-Fetch-Site: same-site` too, for sibling subdomains you trust. Default false. */
  readonly allowSameSite?: boolean;
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

export interface AuthModuleOptions<U extends AuthUser = AuthUser> {
  /** The `createAuth(...)` result. */
  readonly auth: NestAuth<U>;
  /**
   * How many reverse proxies sit in front of the app, counted from the right
   * of `X-Forwarded-For` (see `trustedHopsFromEnv`). 0 when none.
   */
  readonly trustedHops: number;
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
}

/** How long shutdown waits for background work by default. */
export const DEFAULT_SHUTDOWN_TIMEOUT: Duration = '10s';

/** The options after the boot checks, with secrets as bytes and cookie names fixed. */
export interface ResolvedOptions {
  readonly auth: NestAuth;
  readonly trustedHops: number;
  readonly roles: ((user: AuthUser) => readonly string[] | Promise<readonly string[]>) | undefined;
  readonly secure: boolean;
  readonly shutdownTimeout: Duration;
  readonly csrf: {
    readonly secrets: readonly Uint8Array[];
    readonly allowedOrigins: readonly string[];
    readonly allowSameSite: boolean;
    readonly exempt: readonly (string | RegExp)[];
    readonly headerName: string;
    readonly cookieName: string;
    readonly preSessionCookieName: string;
  };
}

const HEADER = /^[a-z0-9-]+$/u;

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

  if (!Number.isSafeInteger(trustedHops) || trustedHops < 0 || trustedHops > MAX_TRUSTED_HOPS) {
    throw new AuthConfigError(
      `trustedHops must be a whole number of proxies from 0 to ${MAX_TRUSTED_HOPS}`,
    );
  }

  if (csrf.secrets.length === 0)
    throw new AuthConfigError('csrf.secrets needs at least one secret');
  if (csrf.allowedOrigins.length === 0) throw new AuthConfigError('csrf.allowedOrigins is empty');

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

  return {
    auth,
    trustedHops,
    roles: options.roles as ResolvedOptions['roles'],
    secure,
    shutdownTimeout: options.shutdownTimeout ?? DEFAULT_SHUTDOWN_TIMEOUT,
    csrf: {
      secrets,
      allowedOrigins: [...csrf.allowedOrigins],
      allowSameSite: csrf.allowSameSite ?? false,
      exempt: [...(csrf.exempt ?? [])],
      headerName,
      cookieName: secure ? '__Host-csrf' : 'csrf',
      preSessionCookieName: secure ? '__Host-presession' : 'presession',
    },
  };
}
