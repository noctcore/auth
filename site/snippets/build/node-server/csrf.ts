import { randomBytes } from 'node:crypto';
import {
  createCsrfToken,
  verifyCsrfToken,
  verifyFetchSite,
  verifyRequestOrigin,
  type CookieSpec,
  type StoredSession,
} from '@noctcore/auth';
import { config } from './config';

const secret = new TextEncoder().encode(config.csrfSecret);
const csrfCookie = config.secureCookies ? '__Host-csrf' : 'csrf';
const preSessionCookie = config.secureCookies ? '__Host-presession' : 'presession';
const PRE_SESSION = /^[0-9a-f]{32}$/u;

/** Signed in: bind to the session. Signed out: bind to this browser's own random id. */
function binding(session: StoredSession | null, preSession: string | null): string | null {
  if (session) return `session:${session.id}`;

  return preSession ? `pre:${preSession}` : null;
}

/** The valid pre-session id from the request's cookies, if any. */
export function readPreSession(cookies: Map<string, string>): string | null {
  const value = cookies.get(preSessionCookie);

  return value && PRE_SESSION.test(value) ? value : null;
}

/** A fresh pre-session id for a signed-out browser, in an HttpOnly cookie. */
export function newPreSession(): { id: string; cookie: CookieSpec } {
  const id = randomBytes(16).toString('hex');
  const attributes = {
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: 'lax',
    path: '/',
  } as const;

  return { id, cookie: { name: preSessionCookie, value: id, attributes } };
}

/** A token for the current binding: the page reads the cookie and echoes it in X-CSRF-Token. */
export function issueCsrfToken(
  session: StoredSession | null,
  preSession: string | null,
): { token: string; cookie: CookieSpec } {
  const token = createCsrfToken(secret, binding(session, preSession) ?? '');
  const attributes = {
    httpOnly: false,
    secure: config.secureCookies,
    sameSite: 'lax',
    path: '/',
  } as const;

  return { token, cookie: { name: csrfCookie, value: token, attributes } };
}

/** All three layers, for every unsafe method. */
export function csrfAllowed(input: {
  method: string;
  origin: string | undefined;
  secFetchSite: string | undefined;
  headerToken: string | undefined;
  cookies: Map<string, string>;
  session: StoredSession | null;
}): boolean {
  const { method } = input;

  if (method === 'GET' || method === 'HEAD') return true;

  const originOk = verifyRequestOrigin({
    method,
    origin: input.origin,
    allowedOrigins: [config.origin],
  });

  // Sec-Fetch-Site whenever the browser sends it; the Origin check covers older browsers.
  const siteOk =
    input.secFetchSite === undefined ||
    verifyFetchSite({ method, secFetchSite: input.secFetchSite });

  const bound = binding(input.session, readPreSession(input.cookies));

  const tokenOk =
    bound !== null &&
    verifyCsrfToken({
      cookieToken: input.cookies.get(csrfCookie),
      headerToken: input.headerToken,
      binding: bound,
      secrets: [secret],
    });

  return originOk && siteOk && tokenOk;
}
