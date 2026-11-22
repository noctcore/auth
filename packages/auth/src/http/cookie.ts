/**
 * Cookie attributes for the session token.
 *
 * - `__Host-` prefix whenever the cookie is Secure: the browser then refuses it
 *   unless it is Secure, has `Path=/` and no `Domain`, so a sibling subdomain
 *   cannot set or overwrite it (cookie tossing).
 * - `HttpOnly`: script cannot read the token, so an XSS cannot exfiltrate it.
 * - `SameSite` per client origin: `Lax` for the web, `None` only for origins
 *   that need it (a desktop shell serving from `app://`), never `None` without
 *   `Secure`.
 * - A session that was not "remembered" gets a browser-session cookie (no
 *   Max-Age), so closing the browser ends it on the client side too.
 *
 * Guide: Learn, "Sessions and expiry".
 */
import { AuthConfigError } from '../shared/errors';

export type SameSite = 'lax' | 'strict' | 'none';

export interface CookieAttributes {
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly sameSite: SameSite;
  readonly path: string;
  /** Seconds. Absent means a browser-session cookie. */
  readonly maxAge?: number;
}

export interface CookieSpec {
  readonly name: string;
  readonly value: string;
  readonly attributes: CookieAttributes;
}

export interface SessionCookieConfig {
  /** Base name; `__Host-` is prepended when secure. Default `session`. */
  readonly name?: string;
  /** Default true. Turn off only for plain-HTTP local development. */
  readonly secure?: boolean;
  /** A fixed value or a function of the request's Origin. Default `lax`. */
  readonly sameSite?: SameSite | ((origin: string | undefined) => SameSite);
}

const NAME = /^[A-Za-z0-9_-]+$/u;
const SAME_SITE: readonly unknown[] = ['lax', 'strict', 'none'];

export function sessionCookieName(config: SessionCookieConfig = {}): string {
  const base = config.name ?? 'session';

  if (!NAME.test(base)) throw new AuthConfigError(`Invalid cookie name: ${base}`);

  return (config.secure ?? true) ? `__Host-${base}` : base;
}

/**
 * The session cookie's `SameSite` for a request with this `Origin`. Every
 * cookie that has to travel with the session cookie (the trusted-device
 * cookie, an adapter's CSRF and pre-session cookies, the blank cookie that
 * clears it) takes its value from here, so a shell that gets `None` for the
 * session gets `None` for the rest too. `None` without Secure is refused.
 */
export function resolveSameSite(config: SessionCookieConfig, origin: string | undefined): SameSite {
  const sameSite =
    typeof config.sameSite === 'function' ? config.sameSite(origin) : (config.sameSite ?? 'lax');

  // `'None'` would skip the Secure check below and still be written as `None`.
  if (!SAME_SITE.includes(sameSite))
    throw new AuthConfigError(`session.cookie.sameSite must be 'lax', 'strict' or 'none'`);

  if (sameSite === 'none' && !(config.secure ?? true)) {
    throw new AuthConfigError('SameSite=None requires a Secure cookie');
  }

  return sameSite;
}

function attributes(
  config: SessionCookieConfig,
  origin: string | undefined,
  maxAge?: number,
): CookieAttributes {
  const secure = config.secure ?? true;
  const sameSite = resolveSameSite(config, origin);

  return maxAge === undefined
    ? { httpOnly: true, secure, sameSite, path: '/' }
    : { httpOnly: true, secure, sameSite, path: '/', maxAge };
}

export function createSessionCookie(
  config: SessionCookieConfig,
  token: string,
  options: { expiresAt: number; persistent: boolean; now: number; origin?: string | undefined },
): CookieSpec {
  const maxAge = options.persistent
    ? Math.max(0, Math.floor((options.expiresAt - options.now) / 1000))
    : undefined;

  return {
    name: sessionCookieName(config),
    value: token,
    attributes: attributes(config, options.origin, maxAge),
  };
}

/** The cookie that clears the session cookie on logout. */
export function createBlankSessionCookie(config: SessionCookieConfig, origin?: string): CookieSpec {
  return { name: sessionCookieName(config), value: '', attributes: attributes(config, origin, 0) };
}

/** A fixed cookie name, with `__Host-` prepended when the session cookie is secure. */
export function prefixedCookieName(config: SessionCookieConfig, base: string): string {
  return (config.secure ?? true) ? `__Host-${base}` : base;
}

/** Name of the trusted-device cookie: `__Host-device` when secure. */
export function deviceCookieName(config: SessionCookieConfig = {}): string {
  return prefixedCookieName(config, 'device');
}

/** A long-lived HttpOnly cookie named `base`, with the session cookie's other attributes. */
export function longLivedCookie(
  config: SessionCookieConfig,
  base: string,
  token: string,
  maxAge: number,
  origin?: string,
): CookieSpec {
  return {
    name: prefixedCookieName(config, base),
    value: token,
    attributes: attributes(config, origin, maxAge),
  };
}

/** The trusted-device cookie: HttpOnly, long-lived, same attributes as the session cookie otherwise. */
export function deviceCookie(
  config: SessionCookieConfig,
  token: string,
  maxAge: number,
  origin?: string,
): CookieSpec {
  return longLivedCookie(config, 'device', token, maxAge, origin);
}

/** `Set-Cookie` header value, for servers without a cookie helper of their own. */
export function serializeCookie(spec: CookieSpec): string {
  const parts = [`${spec.name}=${encodeURIComponent(spec.value)}`, `Path=${spec.attributes.path}`];

  if (spec.attributes.maxAge !== undefined) parts.push(`Max-Age=${spec.attributes.maxAge}`);
  if (spec.attributes.httpOnly) parts.push('HttpOnly');
  if (spec.attributes.secure) parts.push('Secure');

  parts.push(
    `SameSite=${spec.attributes.sameSite[0]?.toUpperCase()}${spec.attributes.sameSite.slice(1)}`,
  );

  return parts.join('; ');
}

/** Reads a `Cookie` request header. Later duplicates do not override the first value. */
export function parseCookieHeader(header: string | null | undefined): Map<string, string> {
  const cookies = new Map<string, string>();

  if (!header) return cookies;

  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=');

    if (eq <= 0) continue;

    const name = pair.slice(0, eq).trim();

    if (cookies.has(name)) continue;

    const raw = pair.slice(eq + 1).trim();

    try {
      cookies.set(name, decodeURIComponent(raw));
    } catch {
      // A malformed escape is not a value we can trust; skip it.
    }
  }

  return cookies;
}
