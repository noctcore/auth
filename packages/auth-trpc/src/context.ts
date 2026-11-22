/**
 * The request's auth state, resolved once per HTTP request when tRPC builds
 * the context, and shared by every procedure of a batch.
 *
 * - The session is validated through the core only (`readSessionToken` and
 *   `validateRequest`), so a middleware can never disagree with the core
 *   about who is signed in. The user id comes from the stored session, never
 *   from a header, the input or the client. Whether the request counts as
 *   activity (`touch`) is decided before that one validation, from the
 *   procedure calls tRPC parsed: a batch touches when any call is active.
 * - The CSRF verdict is computed here, from the request's headers, and
 *   enforced by the `csrf` middleware on every mutation (the core's three
 *   checks: Origin allowlist, `Sec-Fetch-Site` (`cross-site` only from an
 *   origin on `crossSiteOrigins`), and the signed double-submit token bound
 *   to this session or pre-session). The verdict and the safe request
 *   handout are the core's (`csrfRequestAllowed`, `handOutCsrfToken`), the
 *   same functions the Nest adapter calls.
 * - Every cookie the adapter sets takes the session cookie's `SameSite` for
 *   the request's `Origin` (the core's `resolveSameSite`), so a shell that
 *   gets `None` for its session gets it for the CSRF cookies too.
 * - Like the Nest adapter, a safe request hands out what the page needs to
 *   send mutations: a pre-session id when the browser has none yet, and a
 *   CSRF cookie bound to the current binding. `ctx.auth.csrfToken()` returns
 *   that same token for a client that cannot read the cookie (a desktop
 *   shell on its own scheme, a web app on another origin than the API). A session token the core
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
  bindCsrfToSession,
  clearsSessionCookie,
  csrfRequestAllowed,
  handOutCsrfToken,
  isSafeMethod,
  readCsrfCookies,
  resolveSameSite,
  startCsrfPreSession,
  type AuthUser,
  type CookieSpec,
  type IssuedSession,
  type RequestMeta,
  type ValidatedSession,
} from '@noctcore/auth';
import { internalError } from './errors';
import { resolveOptions, type AuthContextOptions, type ResolvedOptions } from './options';
import {
  fromFetch,
  fromNode,
  requestMeta,
  type CookieWriter,
  type FetchContextInput,
  type HeaderWriter,
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
  /**
   * The CSRF token for the request's session or pre-session, for a client
   * that cannot read the `csrf` cookie: return it from a public query. It is
   * exactly the token this response sets or keeps as the cookie, minted with
   * the pre-session when missing, as on any query sent with GET. The
   * response is marked `Cache-Control: no-store`, but tRPC lets the headers
   * of your `responseMeta` replace or join that one: wrap it in
   * `authResponseMeta` (or pass `authResponseMeta()` when you have none),
   * which drops these headers yours returns: `Cache-Control`,
   * `Surrogate-Control`, `CDN-Cache-Control`, every `*-CDN-Cache-Control`,
   * `X-Accel-Expires` and `Edge-Control`. A proxy-specific cache header
   * outside this list is not touched; keep such rules off the token route,
   * and keep the query out of any caching rule. On nestjs-trpc 2.14.0 and
   * later, pass it as `trpc: { responseMeta: authResponseMeta(yours) }`;
   * before 2.14.0 there is no `responseMeta`, so keep cache-setting
   * middleware off the base path or serve the token from Nest with
   * `SessionCookies.csrfToken`.
   * The token stays bound to the session or pre-session and the cookie is
   * still required next to it. Whatever your CORS setup lets a page on
   * another origin read, its unsafe requests are refused on the `Origin`
   * allowlist and `Sec-Fetch-Site`, whatever the token, so a read token is
   * useless cross-site. Throws an `AuthConfigError` on a request
   * sent with an unsafe method (where nothing is minted), on a streamed
   * batch (`httpBatchStreamLink`) and on a subscription, whose headers go
   * out before any procedure runs.
   */
  csrfToken(): { csrfToken: string };
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
  /**
   * Set when a procedure of the request returned `ctx.auth.csrfToken()`, so
   * `authResponseMeta` keeps the app's `responseMeta` from replacing the
   * `Cache-Control: no-store` the call set.
   */
  readonly tokenHandedOut: { value: boolean };
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

/** A procedure whose meta says `touch: false` never counts as activity. */
const isPassiveMeta = (meta: unknown): boolean =>
  (meta as { touch?: unknown } | null | undefined)?.touch === false;

/**
 * Whether the request refreshes the session's last-active time: when any of
 * its calls is active, or when tRPC named no call (an adapter that passes no
 * `info`), as before the option existed.
 */
function touches(options: ResolvedOptions, request: HttpRequest): boolean {
  const { touch } = options;

  if (touch === false) return false;
  if (request.calls.length === 0) return true;

  return request.calls.some(
    (call) => !isPassiveMeta(call.procedure?._def?.meta) && touch(call.path),
  );
}

async function resolveState(
  options: ResolvedOptions,
  request: HttpRequest,
  write: CookieWriter,
  setHeader: HeaderWriter,
): Promise<AuthState> {
  const { auth, csrf } = options;
  const meta = requestMeta(request, options);
  const cookieHeader = request.header('cookie');
  const token = auth.readSessionToken(cookieHeader);

  const validated =
    token === null
      ? null
      : await auth.validateRequest({ token, meta, touch: touches(options, request) });

  const session = validated?.ok ? validated.value : null;
  const cookies = readCsrfCookies(csrf, cookieHeader);
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

  // Judged as the unsafe request a mutation always is, whatever method carried it.
  const csrfOk = csrfRequestAllowed(csrf, {
    session,
    cookies,
    origin: request.header('origin'),
    secFetchSite: request.header('sec-fetch-site'),
    headerToken: request.header(csrf.headerName),
  });

  const streamed = isStreamedRequest((name) => request.header(name));
  // The token this response sets or keeps as the cookie, on a safe request.
  let handed: string | undefined;

  if (isSafeMethod(request.method)) {
    const handout = handOutCsrfToken(options, { session, cookies, sameSite });

    for (const cookie of handout.cookies) write(cookie);

    handed = handout.token;
  }

  const tokenHandedOut = { value: false };

  const csrfToken = (): { csrfToken: string } => {
    if (handed === undefined || streamed || request.subscription) {
      throw new AuthConfigError(
        'ctx.auth.csrfToken() needs a query sent with GET through httpLink or httpBatchLink: ' +
          'a request with an unsafe method mints no token, and a streamed batch ' +
          '(httpBatchStreamLink) or a subscription sends its headers before any procedure runs.',
      );
    }

    setHeader('cache-control', 'no-store');
    tokenHandedOut.value = true;

    return { csrfToken: handed };
  };

  let user: Promise<AuthUser | null> | undefined;

  const startPreSession = (): { csrfToken: string } => {
    const fresh = startCsrfPreSession(options, sameSite);

    for (const cookie of fresh.cookies) write(cookie);

    return { csrfToken: fresh.token };
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
      const next = bindCsrfToSession(options, issued.session, issued.cookie.attributes.sameSite);

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
    csrfToken,
    user: () => {
      user ??= session ? auth.context.users.findById(session.userId) : Promise.resolve(null);

      return user;
    },
    // Not on the type; here so a call from untyped code gets the reason.
    ...refusingWriters,
  };

  const state: AuthState = base;

  internals.set(state, {
    options,
    csrfOk,
    streamed,
    writers,
    slot: { claimed: false },
    tokenHandedOut,
  });

  return state;
}

/**
 * Refuses a Node `res` that cannot read and set headers. The socket tRPC's
 * WebSocket adapter (`applyWSSHandler`) passes is one: that adapter builds
 * the context once per connection, while the context hands out cookies and
 * validates the session once per request, so on a socket a first visit would
 * crash and a signed-in connection would keep its session after a sign-out
 * or a revocation. A Fastify reply is another (`setHeader` lives on
 * `reply.raw`); Fastify is not supported yet either. Thrown before anything
 * is read, so no such request gets a context.
 */
function refuseHeaderlessResponse(res: unknown): void {
  const { getHeader, setHeader } = (res ?? {}) as Partial<NodeContextInput['res']>;

  if (typeof getHeader !== 'function' || typeof setHeader !== 'function') {
    throw new AuthConfigError(
      'createAuthContext(...).node needs a Node HTTP response, and got a response that cannot ' +
        "set headers (for example the WebSocket adapter's socket or a Fastify reply). The " +
        'context sets cookies and validates the session once per request, so a WebSocket ' +
        'connection would fail on a first visit and keep a revoked session until it closes. ' +
        'WebSocket and Fastify are not supported yet.',
    );
  }
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
  /**
   * For the Node adapters (standalone, Express, nestjs-trpc): `createContext: (opts) => authContext.node(opts)`.
   * The WebSocket and Fastify adapters are not supported yet: a `res` that
   * cannot set headers (the socket, a Fastify reply) is refused with an
   * `AuthConfigError`.
   */
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
    setHeader: HeaderWriter;
  }): Promise<{ auth: AuthState<U, A> }> => {
    try {
      const state = await resolveState(resolved, pair.request, pair.write, pair.setHeader);

      return { auth: state as AuthState<U, A> };
    } catch (error) {
      resolved.auth.context.logger.error('auth-trpc could not resolve the request', {
        error: error instanceof Error ? error.name : typeof error,
      });

      throw internalError();
    }
  };

  return {
    fetch: (input, peer) => create(fromFetch(input, peer?.remoteAddress)),
    node: async (input) => {
      refuseHeaderlessResponse(input.res);

      return create(fromNode(input));
    },
  };
}
