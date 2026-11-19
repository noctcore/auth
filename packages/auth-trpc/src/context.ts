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
 *   checks: Origin allowlist, `Sec-Fetch-Site` (`cross-site` only from an
 *   origin on `crossSiteOrigins`), and the signed double-submit token bound
 *   to this session or pre-session).
 * - Every cookie the adapter sets takes the session cookie's `SameSite` for
 *   the request's `Origin` (the core's `resolveSameSite`), so a shell that
 *   gets `None` for its session gets it for the CSRF cookies too.
 * - Like the Nest adapter, a safe request hands out what the page needs to
 *   send mutations: a pre-session id when the browser has none yet, and a
 *   CSRF cookie bound to the current binding. A session token the core
 *   refused for good is cleared, so the browser stops sending it
 *   (`clearsSessionCookie`).
 * - A new session (sign-in and every rotation) is written with
 *   `ctx.auth.setSession(issued)`, which also binds a fresh CSRF token to it.
 *   Only a procedure marked `writesCookies` gets the writers: anywhere else
 *   they are missing from the type and refuse at run time.
 * - On a streamed batch (`httpBatchStreamLink`) the response headers are sent
 *   before any procedure runs, so `writesCookies` refuses the call there
 *   before the flow runs.
 * - One procedure per request writes cookies: the first `writesCookies` of a
 *   batch claims the slot and a second is refused before it runs. As a
 *   backstop, a second `setSession`, `signOut` or `clearSession` in one
 *   request throws before writing.
 *
 * A failure to resolve (a store down) answers `internal`, logging only the
 * error's name: a store error can carry the session key.
 */
import {
  AuthConfigError,
  clearsSessionCookie,
  parseCookieHeader,
  resolveSameSite,
  verifyFetchSite,
  verifyRequestOrigin,
  type AuthUser,
  type CookieSpec,
  type IssuedSession,
  type RequestMeta,
  type ValidatedSession,
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

/**
 * `ctx.auth`: what the adapter knows about the request. It cannot write
 * cookies: only a procedure marked `writesCookies` gets `ctx.auth` as an
 * `AuthWriter`, with `setSession`, `signOut` and `clearSession`.
 */
export interface AuthState<U extends AuthUser = AuthUser, A = unknown> {
  /**
   * The session the core accepted, or null when there is none or it was
   * refused. Under the two-factor plugin's `enforcement` it carries
   * `twoFactor` (grace or enrollment-only) for this request.
   */
  readonly session: ValidatedSession<A> | null;
  /** Client IP through the trusted hops, user agent and origin: pass it to the flows. */
  readonly meta: RequestMeta;
  /** The trusted-device token from its cookie, for `auth.login({ deviceToken })`. */
  readonly deviceToken: string | null;
  /** The session's user, loaded from the store once per request; null when signed out or deleted. */
  user(): Promise<U | null>;
}

/**
 * `ctx.auth` in a procedure marked `writesCookies` (`WritesCookiesMiddleware`
 * on nestjs-trpc). In any other procedure these three do not exist on the
 * type, and at run time they throw an `AuthConfigError` before writing
 * anything (`signOut` before the core signs out).
 */
export interface AuthWriter<U extends AuthUser = AuthUser, A = unknown> extends AuthState<U, A> {
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

type Writers = Pick<AuthWriter, 'setSession' | 'signOut' | 'clearSession'>;

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
  /** The real cookie writers, handed out by `writesCookies` only. */
  readonly writers: Writers;
  /**
   * The request's one cookie-writer slot, shared by every procedure of a
   * batch: `writesCookies` claims it, and a second claim is refused.
   */
  readonly slot: { claimed: boolean };
}

/** The header value `httpBatchStreamLink` sends; tRPC answers it with a streamed body. */
const STREAMED = 'application/jsonl';

/**
 * Whether tRPC will stream this request's response, decided exactly as
 * tRPC's own `getAcceptHeader` does: the `trpc-accept` header when present
 * (whatever its value), otherwise the standard `Accept` header when any of
 * its comma-separated parts, trimmed, is `application/jsonl`. The comparison
 * is case-sensitive, as tRPC's is.
 */
export function isStreamedRequest(header: (name: string) => string | undefined): boolean {
  const accept = header('accept');

  const chosen =
    header('trpc-accept') ??
    (accept?.split(',').some((part) => part.trim() === STREAMED) ? STREAMED : undefined);

  return chosen === STREAMED;
}

/**
 * Refuses a cookie write on a streamed response, where it would be lost (the
 * fetch adapter) or throw after the flow ran (Node). Run by `writesCookies`
 * before the procedure.
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

/**
 * Claims the request's one cookie-writer slot for a procedure marked
 * `writesCookies`, before it runs. Every procedure of a batch shares
 * `ctx.auth`, so two session writers in one batch (two sign-ins, a sign-in
 * and a rotation) would both run, the browser would keep the last cookie, and
 * the other session would stay live in the store with no browser holding it.
 */
export function claimCookieWriter(found: Internals): void {
  if (found.slot.claimed) {
    throw new AuthConfigError(
      'Only one procedure per request can write cookies, and this batch already has one. ' +
        'Send session-writing mutations one per request (httpLink, for example with splitLink).',
    );
  }

  found.slot.claimed = true;
}

const internals = new WeakMap<object, Internals>();

export function internalsOf(state: unknown): Internals | undefined {
  return typeof state === 'object' && state !== null ? internals.get(state) : undefined;
}

function unmarked(): never {
  throw new AuthConfigError(
    'Only a procedure marked writesCookies (WritesCookiesMiddleware on nestjs-trpc) can call ' +
      'setSession, signOut or clearSession: add it in front of the procedure.',
  );
}

/** What an unmarked procedure finds in place of the writers: refusals, before anything runs. */
const refusingWriters: Writers = {
  setSession: unmarked,
  signOut: unmarked,
  clearSession: unmarked,
};

/**
 * `ctx.auth` for a procedure marked `writesCookies`: the same request state,
 * with the writers. A view per procedure, so marking one procedure of a
 * batch never lets another write.
 */
export function writerView(state: AuthState, found: Internals): AuthWriter {
  const view: AuthWriter = { ...state, ...found.writers };

  internals.set(view, found);

  return view;
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
  const origin = request.header('origin');

  const originOk = verifyRequestOrigin({ method, origin, allowedOrigins: csrf.allowedOrigins });

  // Fetch metadata, when the browser sends it. A client that sends none (an
  // old browser, a native client) still needs the allowed Origin and the token.
  const fetchSiteOk = verifyFetchSite({
    method,
    secFetchSite,
    allowSameSite: csrf.allowSameSite,
    origin,
    crossSiteOrigins: csrf.crossSiteOrigins,
  });

  const siteOk = fetchSiteOk || secFetchSite === undefined;

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
  const meta = requestMeta(request, options);
  const cookieHeader = request.header('cookie');
  const token = auth.readSessionToken(cookieHeader);
  const validated = token === null ? null : await auth.validateRequest({ token, meta });
  const session = validated?.ok ? validated.value : null;
  const cookies = parseCookieHeader(cookieHeader);
  const preSession = readPreSession(cookies.get(csrf.preSessionCookieName));
  const cookieToken = cookies.get(csrf.cookieName);
  let bound = binding(session, preSession);
  // Every cookie set here travels with the session cookie, so takes its SameSite.
  const sameSite = resolveSameSite(options.cookie, request.header('origin'));

  // A token the core refused for good is cleared, so the browser stops
  // sending it. One another request may still be adopting is kept.
  if (validated !== null && clearsSessionCookie(validated)) {
    write({
      name: auth.cookieName,
      value: '',
      attributes: { httpOnly: true, secure: options.secure, sameSite, path: '/', maxAge: 0 },
    });
  }

  const csrfOk = csrfVerdict(options, request, bound, cookieToken);
  const streamed = isStreamedRequest((name) => request.header(name));

  if (isSafeMethod(request.method)) {
    if (bound === null) {
      const fresh = newPreSession(options, sameSite);

      write(fresh.cookie);
      bound = preSessionBinding(fresh.id);
    }

    const current = csrfTokenValid(options, { cookieToken, headerToken: cookieToken, bound });

    if (!current) write(csrfCookie(options, bound, sameSite).cookie);
  }

  let user: Promise<AuthUser | null> | undefined;

  const startPreSession = (): { csrfToken: string } => {
    const fresh = newPreSession(options, sameSite);
    const next = csrfCookie(options, preSessionBinding(fresh.id), sameSite);

    write(fresh.cookie);
    write(next.cookie);

    return { csrfToken: next.token };
  };

  // The backstop behind the slot: one write per request, whoever calls it.
  let written = false;

  const once = (): void => {
    if (written) {
      throw new AuthConfigError(
        'This request already wrote its session cookie: setSession, signOut and clearSession ' +
          'run at most once per request, together.',
      );
    }

    written = true;
  };

  const writers: Writers = {
    setSession: (issued) => {
      once();

      // The CSRF cookie goes wherever the session cookie goes.
      const next = csrfCookie(
        options,
        sessionBinding(issued.session),
        issued.cookie.attributes.sameSite,
      );

      write(issued.cookie);
      write(issued.deviceCookie);
      write(next.cookie);

      return { csrfToken: next.token };
    },
    signOut: async () => {
      once();

      const { cookie } = await auth.logout({ token, meta });

      write(cookie);

      return startPreSession();
    },
    clearSession: (cookie) => {
      once();
      write(cookie);

      return startPreSession();
    },
  };

  const base = {
    session,
    meta,
    deviceToken: auth.readDeviceToken(cookieHeader),
    user: () => {
      user ??= session ? auth.context.users.findById(session.userId) : Promise.resolve(null);

      return user;
    },
    // Not on the type; here so a call from untyped code gets the reason.
    ...refusingWriters,
  };

  const state: AuthState = base;

  internals.set(state, { options, csrfOk, streamed, writers, slot: { claimed: false } });

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
