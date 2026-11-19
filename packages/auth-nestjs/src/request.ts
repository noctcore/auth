/**
 * What the module knows about one request, resolved once and shared by the
 * CSRF middleware, the guard and the parameter decorators.
 *
 * - The session is validated through the core only (`readSessionToken` and
 *   `validateRequest`), once per request, so the middleware and the guard can
 *   never disagree about who is signed in.
 * - The client IP comes from the core's `clientIp`, through the configured
 *   trusted proxies (and the trusted client IP header, when one is set);
 *   Express's `req.ip` and its trust-proxy setting are never read.
 * - Nothing here trusts an identity the client wrote: the user id comes from
 *   the stored session, never from a header or the body.
 *
 * State lives in WeakMaps keyed by the raw Node request, which is the same
 * object under Express (where `req` is it) and Fastify (where `req.raw` is).
 */
import type { IncomingHttpHeaders } from 'node:http';
import {
  clearsSessionCookie,
  clientIp,
  resolveSameSite,
  serializeCookie,
  type AuthUser,
  type CookieSpec,
  type RequestMeta,
  type SameSite,
  type ValidatedSession,
} from '@noctcore/auth';
import type { ResolvedOptions } from './options';

/** The raw Node request, as far as the module reads it. */
export interface RawRequest {
  readonly headers: IncomingHttpHeaders;
  readonly method?: string | undefined;
  readonly url?: string | undefined;
  readonly originalUrl?: string | undefined;
  readonly socket?: { readonly remoteAddress?: string | undefined } | undefined;
}

/** The raw Node response, as far as the module writes it. */
export interface RawResponse {
  statusCode: number;
  getHeader(name: string): number | string | string[] | undefined;
  setHeader(name: string, value: number | string | readonly string[]): unknown;
  end(body?: string): unknown;
}

export interface SessionState {
  /** The session token from the cookie, or null when there is none. */
  readonly token: string | null;
  /** The validated session (with its standing on this request), or null when there is none or it was refused. */
  readonly session: ValidatedSession<unknown> | null;
  /** True when the core refused the token for good, so the response clears its cookie (`clearsSessionCookie`). */
  readonly clearCookie: boolean;
  readonly meta: RequestMeta;
}

/** Who the guard let through, for the parameter decorators. */
export interface Principal extends SessionState {
  readonly user: AuthUser | null;
}

const states = new WeakMap<object, Promise<SessionState>>();
const principals = new WeakMap<object, Principal>();
const csrfChecked = new WeakSet<object>();

/** Recorded by CsrfMiddleware when a request passed its checks or is on an exempt path. */
export function markCsrfPassed(req: RawRequest): void {
  csrfChecked.add(req);
}

/** False for a request the CSRF middleware never saw, whatever the reason. */
export function csrfPassed(req: RawRequest): boolean {
  return csrfChecked.has(req);
}

/** Fastify hands Nest a wrapper with the Node request under `raw`; Express hands the request itself. */
export function rawRequest(req: unknown): RawRequest {
  const raw = (req as { raw?: RawRequest }).raw;

  return raw ?? (req as RawRequest);
}

export function rawResponse(res: unknown): RawResponse {
  const raw = (res as { raw?: RawResponse }).raw;

  return raw ?? (res as RawResponse);
}

export function header(req: RawRequest, name: string): string | undefined {
  const value = req.headers[name];

  return Array.isArray(value) ? value[0] : value;
}

export function requestMeta(
  req: RawRequest,
  trust: Pick<ResolvedOptions, 'trustedHops' | 'clientIpHeader'>,
): RequestMeta {
  const origin = header(req, 'origin');

  return {
    ip:
      clientIp({
        remoteAddress: req.socket?.remoteAddress,
        forwardedFor: req.headers['x-forwarded-for'],
        trustedHops: trust.trustedHops,
        trustedHeader:
          trust.clientIpHeader === undefined ? undefined : req.headers[trust.clientIpHeader],
      }) ?? 'unknown',
    userAgent: header(req, 'user-agent') ?? '',
    ...(origin === undefined ? {} : { origin }),
  };
}

/** The request's session, validated at most once however many callers ask. */
export function sessionState(req: RawRequest, options: ResolvedOptions): Promise<SessionState> {
  const cached = states.get(req);

  if (cached) return cached;

  const pending = resolveSession(req, options);

  states.set(req, pending);

  return pending;
}

async function resolveSession(req: RawRequest, options: ResolvedOptions): Promise<SessionState> {
  const meta = requestMeta(req, options);
  const token = options.auth.readSessionToken(header(req, 'cookie'));

  if (token === null) return { token, session: null, clearCookie: false, meta };

  const result = await options.auth.validateRequest({ token, meta });

  return {
    token,
    session: result.ok ? result.value : null,
    clearCookie: clearsSessionCookie(result),
    meta,
  };
}

export function setPrincipal(req: RawRequest, principal: Principal): void {
  principals.set(req, principal);
}

export function principalOf(req: RawRequest): Principal | undefined {
  return principals.get(req);
}

/** Adds a `Set-Cookie` header, keeping the ones already set on the response. */
export function appendCookie(res: RawResponse, spec: CookieSpec): void {
  const previous = res.getHeader('set-cookie');

  const list =
    previous === undefined ? [] : Array.isArray(previous) ? previous : [String(previous)];

  res.setHeader('set-cookie', [...list, serializeCookie(spec)]);
}

/**
 * The session cookie's `SameSite` for this request's `Origin`, for every
 * cookie the module sets alongside it.
 */
export function sameSiteFor(req: RawRequest, options: ResolvedOptions): SameSite {
  return resolveSameSite(options.cookie, header(req, 'origin'));
}

/** A cookie that clears the session cookie, for a token the core refused. */
export function blankSessionCookie(options: ResolvedOptions, sameSite: SameSite): CookieSpec {
  return {
    name: options.auth.cookieName,
    value: '',
    attributes: { httpOnly: true, secure: options.secure, sameSite, path: '/', maxAge: 0 },
  };
}
