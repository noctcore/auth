/**
 * Cross-site request forgery: a page on another site makes the browser send a
 * state-changing request with the user's cookies attached.
 *
 * The checks, on by default in the framework adapters:
 *
 * 0. `verifyFetchSite`: browsers send `Sec-Fetch-Site` on every request and
 *    page script cannot forge it. For an app served from one origin, refusing
 *    unsafe requests unless it says `same-origin` (and refusing it missing) is
 *    the strictest check and the auth guide's first recommendation. Apps with
 *    a desktop shell or sibling subdomains cannot use it alone, which is why
 *    the Origin allowlist below exists.
 * 1. `verifyRequestOrigin`: every unsafe method must carry an `Origin` header
 *    naming an allowed origin. Browsers always send it on cross-site requests,
 *    and a page cannot forge it. A missing or `null` Origin is refused.
 * 2. A signed double-submit token for clients the Origin check cannot cover on
 *    its own (a desktop shell on `app://`, old browsers): the server sets a
 *    token cookie, the client echoes it in a header, and the token is an HMAC
 *    over a binding (the session or a pre-session id) under a server secret, so
 *    a token minted for one session is useless in another. Secret rollover:
 *    pass the current secret first and previous ones after it.
 *
 * Guide: Learn, "CSRF".
 */
import { encodeHexLowerCase } from '@oslojs/encoding';
import { hexDigestsEqual, hmacSha256Hex, secretsEqual } from '../crypto/hash';
import { cryptoRandom, randomBytes, type RandomSource } from '../crypto/random';
import { AuthConfigError } from '../shared/errors';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Upper-cases ASCII letters only. `toUpperCase()` also folds some non-ASCII
 * letters into ASCII ones (a long s becomes "S", a dotless i becomes "I"), which
 * would let a method like `OPTION` plus a long s pass as safe.
 */
function isSafeMethod(method: string): boolean {
  return SAFE_METHODS.has(method.replace(/[a-z]+/gu, (letters) => letters.toUpperCase()));
}

function normalizeOrigin(value: string): string | null {
  try {
    const url = new URL(value);

    // `new URL('app://app').origin` is the string 'null' for non-special
    // schemes, so build scheme://host[:port] by hand.
    return `${url.protocol}//${url.host}`.toLowerCase();
  } catch {
    return null;
  }
}

export function verifyRequestOrigin(input: {
  method: string;
  origin: string | null | undefined;
  allowedOrigins: readonly string[];
}): boolean {
  if (isSafeMethod(input.method)) return true;
  if (!input.origin || input.origin === 'null') return false;

  const origin = normalizeOrigin(input.origin);

  if (origin === null) return false;

  return input.allowedOrigins.some((allowed) => normalizeOrigin(allowed) === origin);
}

/**
 * Refuses unsafe requests whose `Sec-Fetch-Site` is missing or not
 * `same-origin` (or `same-site` when `allowSameSite` is set, for sibling
 * subdomains you trust). Requests from a desktop shell on its own scheme
 * arrive as `cross-site`: list the shell's exact origin in
 * `crossSiteOrigins` and pass the request's `origin`, and a `cross-site`
 * request from that origin passes too. Nothing else that says `cross-site`
 * does, and `none` never does.
 */
export function verifyFetchSite(input: {
  method: string;
  secFetchSite: string | null | undefined;
  allowSameSite?: boolean;
  /** The request's `Origin` header, read only for `crossSiteOrigins`. */
  origin?: string | null | undefined;
  /** Exact origins whose `cross-site` requests are accepted. Default none. */
  crossSiteOrigins?: readonly string[];
}): boolean {
  if (isSafeMethod(input.method)) return true;
  if (input.secFetchSite === 'same-origin') return true;
  if (input.allowSameSite === true && input.secFetchSite === 'same-site') return true;

  // Only relaxes this one check: callers still require the Origin allowlist
  // and the double-submit token. Both headers are set by the browser, and a
  // client that forges them has no victim's cookies to send.
  const listedOrigin = verifyRequestOrigin({
    method: input.method,
    origin: input.origin,
    allowedOrigins: input.crossSiteOrigins ?? [],
  });

  return listedOrigin && input.secFetchSite === 'cross-site';
}

/**
 * Checks an allowlist of origins at boot: each entry must be one exact
 * origin (`scheme://host[:port]`, any scheme, such as `app://desktop`), with
 * no wildcard and not `null`, so a typo fails at startup instead of matching
 * nothing, or more than meant. `option` names the setting in the error.
 */
export function assertExactOrigins(origins: readonly string[], option: string): readonly string[] {
  for (const origin of origins) {
    if (origin.includes('*') || !isBareOrigin(origin)) {
      throw new AuthConfigError(`${option} needs exact origins, such as app://desktop: ${origin}`);
    }
  }

  return [...origins];
}

/**
 * `scheme://host[:port]` and nothing else: a host (so not `app:desktop`,
 * `app://` or `javascript:x`), and no user info, path (beyond `/`), query or
 * fragment, which an origin never carries and a listed entry must not either.
 */
function isBareOrigin(value: string): boolean {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return false;
  }

  return (
    url.host !== '' &&
    url.username === '' &&
    url.password === '' &&
    (url.pathname === '' || url.pathname === '/') &&
    url.search === '' &&
    url.hash === '' &&
    !value.endsWith('?') &&
    !value.endsWith('#')
  );
}

/** Shortest accepted secret. */
export const MIN_CSRF_SECRET_BYTES = 32;
const NONCE = /^[0-9a-f]{32}$/u;

function checkSecret(secret: Uint8Array): void {
  if (secret.byteLength < MIN_CSRF_SECRET_BYTES) {
    throw new AuthConfigError(`CSRF secrets must be at least ${MIN_CSRF_SECRET_BYTES} bytes`);
  }
}

/** The binding is length-prefixed, so no binding and nonce pair can be read as another. */
function mac(secret: Uint8Array, binding: string, nonce: string): string {
  return hmacSha256Hex(secret, `csrf:${binding.length}:${binding}:${nonce}`);
}

/** A token `<nonce>.<hmac>` bound to `binding` under the current secret. */
export function createCsrfToken(
  secret: Uint8Array,
  binding: string,
  random: RandomSource = cryptoRandom,
): string {
  checkSecret(secret);
  const nonce = encodeHexLowerCase(randomBytes(16, random));

  return `${nonce}.${mac(secret, binding, nonce)}`;
}

export function verifyCsrfToken(input: {
  /** The value of the token cookie. */
  cookieToken: string | null | undefined;
  /** The value the client echoed in the header. */
  headerToken: string | null | undefined;
  binding: string;
  /** Current secret first, then previous ones still accepted during rollover. */
  secrets: readonly Uint8Array[];
}): boolean {
  const { cookieToken, headerToken } = input;

  if (input.secrets.length === 0) return false;

  for (const secret of input.secrets) checkSecret(secret);

  if (!cookieToken || !headerToken || !secretsEqual(cookieToken, headerToken)) return false;

  const dot = cookieToken.indexOf('.');

  if (dot <= 0) return false;

  const nonce = cookieToken.slice(0, dot);
  const given = cookieToken.slice(dot + 1);

  if (!NONCE.test(nonce)) return false;

  // Check every secret, without stopping at the first match, so timing does not
  // reveal which secret signed the token.
  let valid = false;

  for (const secret of input.secrets) {
    if (hexDigestsEqual(given, mac(secret, input.binding, nonce))) valid = true;
  }

  return valid;
}
