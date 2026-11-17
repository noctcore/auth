/**
 * The request's auth state, resolved once per HTTP request when tRPC builds
 * the context, and shared by every procedure of a batch.
 *
 * - The session is validated through the core only (`readSessionToken` and
 *   `validateRequest`), so a middleware can never disagree with the core
 *   about who is signed in. The user id comes from the stored session, never
 *   from a header, the input or the client.
 * - The CSRF verdict is computed here, from the request's headers, and
 *   enforced by the `csrf` middleware on every mutation (the core's three
 *   checks: Origin allowlist, `Sec-Fetch-Site`, and the signed double-submit
 *   token bound to this session or pre-session).
 * - Like the Nest adapter, a safe request hands out what the page needs to
 *   send mutations: a pre-session id when the browser has none yet, and a
 *   CSRF cookie bound to the current binding. A session token the core
 *   refused is cleared, so the browser stops sending it.
 * - A new session (sign-in and every rotation) is written with
 *   `ctx.auth.setSession(issued)`, which also binds a fresh CSRF token to it.
 * - On a streamed batch (`httpBatchStreamLink`) the response headers are sent
 *   before any procedure runs. `setSession`, `signOut` and `clearSession`
 *   throw an `AuthConfigError` there instead of losing the cookie, and the
 *   `writesCookies` middleware refuses the call before the flow runs.
 *
 * A failure to resolve (a store down) answers `internal`, logging only the
 * error's name: a store error can carry the session key.
 */
import {
  AuthConfigError,
  parseCookieHeader,
  verifyFetchSite,
  verifyRequestOrigin,
  type AuthUser,
  type CookieSpec,
  type IssuedSession,
  type RequestMeta,
  type StoredSession,
} from '@noctcore/auth';
import {
  binding,
  csrfCookie,
  csrfTokenValid,
  newPreSession,
  preSessionBinding,
  readPreSession,
  sessionBinding,
} from './csrf-tokens';
import { internalError } from './errors';
import { resolveOptions, type AuthContextOptions, type ResolvedOptions } from './options';
import {
  fromFetch,
  fromNode,
  requestMeta,
  type CookieWriter,
  type FetchContextInput,
  type HttpRequest,
  type NodeContextInput,
} from './request';

/** `ctx.auth`: what the adapter knows about the request. */
export interface AuthState<U extends AuthUser = AuthUser, A = unknown> {
  /** The session the core accepted, or null when there is none or it was refused. */
  readonly session: StoredSession<A> | null;
  /** Client IP through the trusted hops, user agent and origin: pass it to the flows. */
  readonly meta: RequestMeta;
  /** The trusted-device token from its cookie, for `auth.login({ deviceToken })`. */
  readonly deviceToken: string | null;
  /** The session's user, loaded from the store once per request; null when signed out or deleted. */
  user(): Promise<U | null>;
  /**
   * Writes an issued session's cookie and its trusted-device cookie, plus a
   * CSRF cookie bound to the new session. Call it on sign-in and on every
   * rotation (re-authentication, a password change, revoking the other
   * sessions, verifying an address). The token is returned for the response.
   */
  setSession(issued: Pick<IssuedSession<unknown>, 'cookie' | 'deviceCookie' | 'session'>): {
    csrfToken: string;
  };
  /**
   * Signs the request's session out through the core (`auth.logout`), clears
   * its cookie and starts a fresh pre-session with a CSRF token bound to it.
   */
  signOut(): Promise<{ csrfToken: string }>;
  /**
   * After a flow that ended the session itself (`auth.sessions.revokeAll`):
   * writes the blank cookie it returned and starts a fresh pre-session.
   */
  clearSession(cookie: CookieSpec): { csrfToken: string };
}

/** What the middlewares read about a request; never on the context itself. */
export interface Internals {
  readonly options: ResolvedOptions;
  /** True when the request passes all three CSRF checks as an unsafe request. */
  readonly csrfOk: boolean;
  /**
   * True on a streamed batch (`httpBatchStreamLink`, header
   * `trpc-accept: application/jsonl`): its response headers go out before
   * any procedure runs, so no procedure can set a cookie.
   */
  readonly streamed: boolean;
}

/** The header value `httpBatchStreamLink` sends; tRPC answers it with a streamed body. */
const STREAMED = 'application/jsonl';

/**
 * Refuses a cookie write on a streamed response, where it would be lost (the
 * fetch adapter) or throw after the flow ran (Node). Run by `writesCookies`
 * before the procedure, and by the writers themselves as a backstop.
 */
export function refuseStreamedWrite(streamed: boolean): void {
  if (streamed) {
    throw new AuthConfigError(
      'This procedure writes cookies, and a streamed batch (httpBatchStreamLink) sends its ' +
        'headers before any procedure runs. Send it through httpBatchLink or httpLink, for ' +
        'example with splitLink.',
    );
  }
}

const internals = new WeakMap<object, Internals>();

export function internalsOf(state: unknown): Internals | undefined {
  return typeof state === 'object' && state !== null ? internals.get(state) : undefined;
}

/**
 * The core's own notion of a safe method (GET, HEAD, OPTIONS, with ASCII-only
 * case folding): `verifyRequestOrigin` passes a safe method whatever the
 * Origin, and refuses an unsafe one with none.
 */
function isSafeMethod(method: string): boolean {
  return verifyRequestOrigin({ method, origin: undefined, allowedOrigins: [] });
}

function csrfVerdict(
  options: ResolvedOptions,
  request: HttpRequest,
  bound: string | null,
  cookieToken: string | undefined,
): boolean {
  const { csrf } = options;
  // Judged as the unsafe request a mutation always is, whatever method carried it.
  const method = 'POST';
  const secFetchSite = request.header('sec-fetch-site');

  const originOk = verifyRequestOrigin({
    method,
    origin: request.header('origin'),
    allowedOrigins: csrf.allowedOrigins,
  });

  const siteOk =
    secFetchSite === undefined ||
    verifyFetchSite({ method, secFetchSite, allowSameSite: csrf.allowSameSite });

  const tokenOk = csrfTokenValid(options, {
    cookieToken,
    headerToken: request.header(csrf.headerName),
    bound,
  });

  return originOk && siteOk && tokenOk;
}

async function resolveState(
  options: ResolvedOptions,
  request: HttpRequest,
  write: CookieWriter,
): Promise<AuthState> {
  const { auth, csrf } = options;
  const meta = requestMeta(request, options.trustedHops);
  const cookieHeader = request.header('cookie');
  const token = auth.readSessionToken(cookieHeader);
  const validated = token === null ? null : await auth.validateRequest({ token, meta });
  const session = validated?.ok ? validated.value : null;
  const cookies = parseCookieHeader(cookieHeader);
  const preSession = readPreSession(cookies.get(csrf.preSessionCookieName));
  const cookieToken = cookies.get(csrf.cookieName);
  let bound = binding(session, preSession);

  // A token the core refused is cleared, so the browser stops sending it.
  if (token !== null && session === null) {
    write({
      name: auth.cookieName,
      value: '',
      attributes: { httpOnly: true, secure: options.secure, sameSite: 'lax', path: '/', maxAge: 0 },
    });
  }

  const csrfOk = csrfVerdict(options, request, bound, cookieToken);
  const streamed = request.header('trpc-accept') === STREAMED;

  if (isSafeMethod(request.method)) {
    if (bound === null) {
      const fresh = newPreSession(options);

      write(fresh.cookie);
      bound = preSessionBinding(fresh.id);
    }

    const current = csrfTokenValid(options, { cookieToken, headerToken: cookieToken, bound });

    if (!current) write(csrfCookie(options, bound).cookie);
  }

  let user: Promise<AuthUser | null> | undefined;

  const startPreSession = (): { csrfToken: string } => {
    const fresh = newPreSession(options);
    const next = csrfCookie(options, preSessionBinding(fresh.id));

    write(fresh.cookie);
    write(next.cookie);

    return { csrfToken: next.token };
  };

  const state: AuthState = {
    session,
    meta,
    deviceToken: auth.readDeviceToken(cookieHeader),
    user: () => {
      user ??= session ? auth.context.users.findById(session.userId) : Promise.resolve(null);

      return user;
    },
    setSession: (issued) => {
      refuseStreamedWrite(streamed);

      const next = csrfCookie(options, sessionBinding(issued.session));

      write(issued.cookie);
      write(issued.deviceCookie);
      write(next.cookie);

      return { csrfToken: next.token };
    },
    signOut: async () => {
      // Before the core signs the session out, not after.
      refuseStreamedWrite(streamed);

      const { cookie } = await auth.logout({ token, meta });

      write(cookie);

      return startPreSession();
    },
    clearSession: (cookie) => {
      refuseStreamedWrite(streamed);
      write(cookie);

      return startPreSession();
    },
  };

  internals.set(state, { options, csrfOk, streamed });

  return state;
}

export interface AuthContextFactory<U extends AuthUser, A = unknown> {
  /**
   * For the fetch adapter: `createContext: (opts) => authContext.fetch(opts)`.
   * A fetch `Request` carries no peer address, so pass it from your server
   * (Bun: `server.requestIP(req)?.address`); without it, and with no trusted
   * hops, every client shares the IP `unknown`.
   */
  fetch(
    input: FetchContextInput,
    peer?: { remoteAddress?: string },
  ): Promise<{
    auth: AuthState<U, A>;
  }>;
  /** For the Node adapters (standalone, Express, nestjs-trpc): `createContext: (opts) => authContext.node(opts)`. */
  node(input: NodeContextInput): Promise<{ auth: AuthState<U, A> }>;
}

/**
 * Checks the options once and returns the context creators. Spread the
 * result into your own context: `async (opts) => ({ ...(await authContext.node(opts)), db })`.
 */
export function createAuthContext<U extends AuthUser, A = unknown>(
  options: AuthContextOptions<U, A>,
): AuthContextFactory<U, A> {
  const resolved = resolveOptions(options);

  const create = async (pair: {
    request: HttpRequest;
    write: CookieWriter;
  }): Promise<{ auth: AuthState<U, A> }> => {
    try {
      return { auth: (await resolveState(resolved, pair.request, pair.write)) as AuthState<U, A> };
    } catch (error) {
      resolved.auth.context.logger.error('auth-trpc could not resolve the request', {
        error: error instanceof Error ? error.name : typeof error,
      });

      throw internalError();
    }
  };

  return {
    fetch: (input, peer) => create(fromFetch(input, peer?.remoteAddress)),
    node: (input) => create(fromNode(input)),
  };
}
