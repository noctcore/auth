/**
 * The cookies of the signed double-submit layer, built on the core's
 * `createCsrfToken` and `verifyCsrfToken`.
 *
 * A token is bound to the session when there is one, and before sign-in to a
 * random pre-session id that only this browser holds (in an HttpOnly cookie),
 * so a token minted in one browser or for one session is useless in another.
 * Every change of session changes the binding, so a new token is handed out
 * whenever a session cookie is set or cleared.
 */
import { randomBytes } from 'node:crypto';
import {
  createCsrfToken,
  verifyCsrfToken,
  type CookieSpec,
  type StoredSession,
} from '@noctcore/auth';
import type { ResolvedOptions } from './options';

const PRE_SESSION = /^[0-9a-f]{32}$/u;

export const sessionBinding = (session: StoredSession<unknown>): string => `session:${session.id}`;

export const preSessionBinding = (id: string): string => `pre:${id}`;

/** Signed in: the session. Signed out: the pre-session id, when the browser has one. */
export function binding(
  session: StoredSession<unknown> | null,
  preSession: string | null,
): string | null {
  if (session) return sessionBinding(session);

  return preSession === null ? null : preSessionBinding(preSession);
}

/** The pre-session id from its cookie, or null when it is missing or not one we could have minted. */
export function readPreSession(value: string | undefined): string | null {
  return value !== undefined && PRE_SESSION.test(value) ? value : null;
}

export function newPreSession(options: ResolvedOptions): { id: string; cookie: CookieSpec } {
  const id = randomBytes(16).toString('hex');

  return {
    id,
    cookie: {
      name: options.csrf.preSessionCookieName,
      value: id,
      attributes: { httpOnly: true, secure: options.secure, sameSite: 'lax', path: '/' },
    },
  };
}

export function csrfCookie(
  options: ResolvedOptions,
  bound: string,
): { token: string; cookie: CookieSpec } {
  const [current] = options.csrf.secrets;
  // resolveOptions refuses an empty list, so `current` is always set.
  const token = createCsrfToken(current as Uint8Array, bound);

  return {
    token,
    cookie: {
      name: options.csrf.cookieName,
      value: token,
      // Readable by the page, which echoes it in the CSRF header.
      attributes: { httpOnly: false, secure: options.secure, sameSite: 'lax', path: '/' },
    },
  };
}

export function csrfTokenValid(
  options: ResolvedOptions,
  input: { cookieToken: string | undefined; headerToken: string | undefined; bound: string | null },
): boolean {
  return (
    input.bound !== null &&
    verifyCsrfToken({
      cookieToken: input.cookieToken,
      headerToken: input.headerToken,
      binding: input.bound,
      secrets: options.csrf.secrets,
    })
  );
}
