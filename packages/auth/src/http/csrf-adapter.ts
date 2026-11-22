/**
 * The signed double-submit layer as the framework adapters run it, in one
 * place, so a Nest app and a tRPC server (or an app that mounts both) apply
 * the same rules to the same cookies.
 *
 * Each function works on a small shape (the cookie header, a few request
 * headers, the session id), never on a framework's request or response: the
 * adapter reads its request, calls these, and writes the cookies they return.
 * What stays in an adapter is only what its framework decides: when a request
 * is judged (an unsafe method on a route that is not exempt, a mutation), how
 * a refusal is answered, and how the handed-out token reaches the client.
 *
 * A token is bound to the session when there is one, and before sign-in to a
 * random pre-session id that only this browser holds (in an HttpOnly cookie),
 * so a token minted in one browser or for one session is useless in another.
 * Every change of session changes the binding, so a new token is handed out
 * whenever a session cookie is set or cleared.
 *
 * Guide: Learn, "CSRF".
 */
import { encodeHexLowerCase } from '@oslojs/encoding';
import { randomBytes } from '../crypto/random';
import { AuthConfigError } from '../shared/errors';
import { parseCookieHeader, serializeCookie, type CookieSpec, type SameSite } from './cookie';
import {
  assertExactOrigins,
  createCsrfToken,
  verifyCsrfToken,
  verifyFetchSite,
  verifyRequestOrigin,
} from './csrf';

/** The CSRF options an adapter takes, before the boot checks. */
export interface CsrfSettingsInput {
  /**
   * Signs the double-submit token. At least 32 bytes each, and not the auth
   * secret. Current secret first, previous ones after it during a rollover: a
   * safe request replaces a token signed by a previous secret with one under
   * the current secret.
   */
  readonly secrets: readonly (string | Uint8Array)[];
  /** Origins allowed to send unsafe requests, such as `https://app.example`. */
  readonly allowedOrigins: readonly string[];
  /** Accept `Sec-Fetch-Site: same-site` too. Default false. */
  readonly allowSameSite?: boolean | undefined;
  /** Exact origins whose `cross-site` requests are accepted. Default none. */
  readonly crossSiteOrigins?: readonly string[] | undefined;
  /** Header the page echoes the token in. Default `x-csrf-token`. */
  readonly headerName?: string | undefined;
}

/** The CSRF options after the boot checks, with secrets as bytes and cookie names fixed. */
export interface CsrfSettings {
  readonly secrets: readonly Uint8Array[];
  /** `allowedOrigins` and `crossSiteOrigins` together: every origin the Origin check accepts. */
  readonly allowedOrigins: readonly string[];
  readonly crossSiteOrigins: readonly string[];
  readonly allowSameSite: boolean;
  readonly headerName: string;
  readonly cookieName: string;
  readonly preSessionCookieName: string;
}

/**
 * What the functions below read of an adapter's resolved options: whether
 * the cookies are Secure (exactly when the session cookie is) and the
 * settings `resolveCsrfSettings` returned.
 */
export interface CsrfContext {
  readonly secure: boolean;
  readonly csrf: CsrfSettings;
}

/** The two cookies of the layer, as the request carried them. */
export interface CsrfCookies {
  /** The pre-session id, or null when missing or not one we could have minted. */
  readonly preSession: string | null;
  /** The CSRF cookie's value, as sent. */
  readonly token: string | undefined;
}

/** A session, as far as a binding reads it. */
export interface CsrfSessionRef {
  readonly id: string;
}

/** A token and the cookies the response sets so the browser holds it. */
export interface CsrfHandout {
  readonly token: string;
  /** In the order to write them: the pre-session id first, when there is one. */
  readonly cookies: readonly CookieSpec[];
}

/** A Node-style response that can read and replace a header (Node `res`, Express, Fastify's `raw`). */
export interface SetCookieTarget {
  getHeader(name: string): number | string | string[] | undefined;
  setHeader(name: string, value: string[]): unknown;
}

const HEADER = /^[a-z0-9-]+$/u;
const PRE_SESSION = /^[0-9a-f]{32}$/u;

/**
 * Checks the CSRF options once at boot, so a weak secret or an empty origin
 * allowlist stops the app before it listens instead of letting it run with a
 * check that quietly passes everything. `secure` names the cookies with the
 * `__Host-` prefix, as the session cookie is named exactly when it is Secure.
 */
export function resolveCsrfSettings(input: CsrfSettingsInput, secure: boolean): CsrfSettings {
  if (input.secrets.length === 0) {
    throw new AuthConfigError('csrf.secrets needs at least one secret');
  }

  const crossSiteOrigins = assertExactOrigins(
    input.crossSiteOrigins ?? [],
    'csrf.crossSiteOrigins',
  );

  if (input.allowedOrigins.length === 0 && crossSiteOrigins.length === 0) {
    throw new AuthConfigError('csrf.allowedOrigins is empty');
  }

  const secrets = input.secrets.map((secret) =>
    typeof secret === 'string' ? new TextEncoder().encode(secret) : secret,
  );

  // The core refuses a short secret when it signs; signing once here moves
  // that refusal to boot.
  for (const secret of secrets) createCsrfToken(secret, 'boot-check');

  const headerName = (input.headerName ?? 'x-csrf-token').toLowerCase();

  if (!HEADER.test(headerName)) {
    throw new AuthConfigError(`Invalid CSRF header name: ${headerName}`);
  }

  return {
    secrets,
    allowedOrigins: [...input.allowedOrigins, ...crossSiteOrigins],
    crossSiteOrigins,
    allowSameSite: input.allowSameSite ?? false,
    headerName,
    cookieName: secure ? '__Host-csrf' : 'csrf',
    preSessionCookieName: secure ? '__Host-presession' : 'presession',
  };
}

/** The pre-session id and the CSRF token from the request's `Cookie` header. */
export function readCsrfCookies(
  csrf: CsrfSettings,
  cookieHeader: string | null | undefined,
): CsrfCookies {
  const cookies = parseCookieHeader(cookieHeader);
  const preSession = cookies.get(csrf.preSessionCookieName);

  return {
    preSession: preSession !== undefined && PRE_SESSION.test(preSession) ? preSession : null,
    token: cookies.get(csrf.cookieName),
  };
}

const sessionBinding = (session: CsrfSessionRef): string => `session:${session.id}`;

const preSessionBinding = (id: string): string => `pre:${id}`;

/** Signed in: the session. Signed out: the pre-session id, when the browser has one. */
function bindingOf(session: CsrfSessionRef | null, preSession: string | null): string | null {
  if (session) return sessionBinding(session);

  return preSession === null ? null : preSessionBinding(preSession);
}

function tokenValid(input: {
  cookieToken: string | undefined;
  headerToken: string | undefined;
  bound: string | null;
  secrets: readonly Uint8Array[];
}): boolean {
  return (
    input.bound !== null &&
    verifyCsrfToken({
      cookieToken: input.cookieToken,
      headerToken: input.headerToken,
      binding: input.bound,
      secrets: input.secrets,
    })
  );
}

/** True when `token` alone is a token for `bound`, signed by one of `secrets`. */
const signedFor = (
  token: string | undefined,
  bound: string | null,
  secrets: readonly Uint8Array[],
): boolean => tokenValid({ cookieToken: token, headerToken: token, bound, secrets });

/**
 * The double-submit check of an unsafe request. The header and the cookie
 * match and are signed by any listed secret for this binding; or, during a
 * rollover, the header still carries a token of a previous secret that the
 * page read before a safe request moved the cookie to the current secret
 * (`handOutCsrfToken`), and the cookie is that current token for the same
 * binding. The second case ends when the previous secret is removed.
 */
function doubleSubmitValid(
  csrf: CsrfSettings,
  input: { cookieToken: string | undefined; headerToken: string | undefined; bound: string | null },
): boolean {
  if (tokenValid({ ...input, secrets: csrf.secrets })) return true;

  const [current, ...previous] = csrf.secrets;

  // With one secret `previous` is empty and verifies nothing.
  return (
    signedFor(input.headerToken, input.bound, previous) &&
    signedFor(input.cookieToken, input.bound, [current as Uint8Array])
  );
}

/**
 * The cookies below take `sameSite` from the caller: the session cookie's
 * resolution for the request (`resolveSameSite`), or the attribute of the
 * session cookie written next to them, so they always travel together.
 */
function newPreSession(
  options: CsrfContext,
  sameSite: SameSite,
): { id: string; cookie: CookieSpec } {
  const id = encodeHexLowerCase(randomBytes(16));

  return {
    id,
    cookie: {
      name: options.csrf.preSessionCookieName,
      value: id,
      attributes: { httpOnly: true, secure: options.secure, sameSite, path: '/' },
    },
  };
}

function csrfCookie(
  options: CsrfContext,
  bound: string,
  sameSite: SameSite,
): { token: string; cookie: CookieSpec } {
  const [current] = options.csrf.secrets;
  // resolveCsrfSettings refuses an empty list, so `current` is always set.
  const token = createCsrfToken(current as Uint8Array, bound);

  return {
    token,
    cookie: {
      name: options.csrf.cookieName,
      value: token,
      // Readable by the page, which echoes it in the CSRF header.
      attributes: { httpOnly: false, secure: options.secure, sameSite, path: '/' },
    },
  };
}

/**
 * The verdict on a request judged as unsafe, whatever method carried it:
 * true when all three checks pass. The `Origin` is on the allowlist
 * (`verifyRequestOrigin`); `Sec-Fetch-Site` says `same-origin`, or
 * `cross-site` from an origin on `crossSiteOrigins` (`verifyFetchSite`),
 * whenever the browser sends it; and the double-submit token matches its
 * cookie and is bound to this session or pre-session (`verifyCsrfToken`),
 * with the rollover allowance `doubleSubmitValid` describes. The adapter
 * decides which requests it judges.
 */
export function csrfRequestAllowed(
  csrf: CsrfSettings,
  request: {
    readonly session: CsrfSessionRef | null;
    readonly cookies: CsrfCookies;
    readonly origin: string | undefined;
    readonly secFetchSite: string | undefined;
    /** The value of the `csrf.headerName` header. */
    readonly headerToken: string | undefined;
  },
): boolean {
  // The checks below read the method only to tell safe from unsafe.
  const method = 'POST';
  const { origin, secFetchSite } = request;

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

  const tokenOk = doubleSubmitValid(csrf, {
    cookieToken: request.cookies.token,
    headerToken: request.headerToken,
    bound: bindingOf(request.session, request.cookies.preSession),
  });

  return originOk && siteOk && tokenOk;
}

/**
 * What a safe request hands out so the page can make unsafe ones: a
 * pre-session id when the browser has no session and no id yet, and a CSRF
 * cookie bound to the current binding. A cookie that already verifies for
 * that binding under the current secret is kept (no cookie is set, its token
 * is returned). One signed by a previous secret is replaced by one under the
 * current secret, so every client moves off a previous secret on its next
 * safe request and the previous secret can be removed once its tokens are
 * gone, instead of waiting for clients that never fetch a new token.
 */
export function handOutCsrfToken(
  options: CsrfContext,
  request: {
    readonly session: CsrfSessionRef | null;
    readonly cookies: CsrfCookies;
    readonly sameSite: SameSite;
  },
): CsrfHandout {
  const cookies: CookieSpec[] = [];
  const cookieToken = request.cookies.token;
  let bound = bindingOf(request.session, request.cookies.preSession);

  if (bound === null) {
    const fresh = newPreSession(options, request.sameSite);

    cookies.push(fresh.cookie);
    bound = preSessionBinding(fresh.id);
  }

  // A token for this binding under the current secret: the cookie already holds it.
  if (signedFor(cookieToken, bound, options.csrf.secrets.slice(0, 1))) {
    return { token: cookieToken as string, cookies };
  }

  const fresh = csrfCookie(options, bound, request.sameSite);

  cookies.push(fresh.cookie);

  return { token: fresh.token, cookies };
}

/**
 * A CSRF cookie bound to a session just issued (sign-in and every rotation).
 * Pass the session cookie's own `sameSite`: the CSRF cookie goes wherever it goes.
 */
export function bindCsrfToSession(
  options: CsrfContext,
  session: CsrfSessionRef,
  sameSite: SameSite,
): { token: string; cookie: CookieSpec } {
  return csrfCookie(options, sessionBinding(session), sameSite);
}

/** A fresh pre-session id and a CSRF cookie bound to it, after a session ended. */
export function startCsrfPreSession(options: CsrfContext, sameSite: SameSite): CsrfHandout {
  const fresh = newPreSession(options, sameSite);
  const next = csrfCookie(options, preSessionBinding(fresh.id), sameSite);

  return { token: next.token, cookies: [fresh.cookie, next.cookie] };
}

/** Adds a `Set-Cookie` header to a Node-style response, keeping the ones already set. */
export function appendSetCookie(res: SetCookieTarget, spec: CookieSpec): void {
  const previous = res.getHeader('set-cookie');

  const list =
    previous === undefined ? [] : Array.isArray(previous) ? previous : [String(previous)];

  res.setHeader('set-cookie', [...list, serializeCookie(spec)]);
}
