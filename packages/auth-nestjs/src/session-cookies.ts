/**
 * Writing a new or ended session onto the response, with the CSRF token that
 * goes with it.
 *
 * A session change is a binding change: the CSRF token of the old session (or
 * of the pre-session) stops verifying the moment the new session cookie
 * lands. So every cookie written here comes with a fresh CSRF cookie bound to
 * the new state, and the token is returned for the response body as well, so
 * the page can make its next unsafe request without another round trip.
 * Rotation (sign-in, re-authentication, a password change, revoking the other
 * sessions, verifying an address) all goes through `set`.
 *
 * A client that cannot read the API's cookies (a desktop shell on its own
 * scheme, a web app on another origin than the API) reads the current token
 * from a safe request with `csrfToken`. That grants nothing a cross-site page
 * could use: the token stays bound to the session or pre-session, the cookie
 * is still required next to it, and CORS keeps the body from other origins.
 */
import { Inject, Injectable } from '@nestjs/common';
import { AuthConfigError, type IssuedSession } from '@noctcore/auth';
import { csrfCookie, newPreSession, preSessionBinding, sessionBinding } from './csrf-tokens';
import type { ResolvedOptions } from './options';
import {
  appendCookie,
  handedCsrfToken,
  principalOf,
  rawRequest,
  rawResponse,
  requestMeta,
  sameSiteFor,
} from './request';
import { AUTH_OPTIONS } from './tokens';

@Injectable()
export class SessionCookies {
  constructor(@Inject(AUTH_OPTIONS) private readonly options: ResolvedOptions) {}

  /**
   * Sets an issued session's cookie and its trusted-device cookie, plus a
   * CSRF cookie bound to it. Pass the response from `@Res({ passthrough: true })`.
   */
  set(
    response: unknown,
    issued: Pick<IssuedSession<unknown>, 'cookie' | 'deviceCookie' | 'session'>,
  ): {
    csrfToken: string;
  } {
    const res = rawResponse(response);

    // The CSRF cookie goes wherever the session cookie goes.
    const csrf = csrfCookie(
      this.options,
      sessionBinding(issued.session),
      issued.cookie.attributes.sameSite,
    );

    appendCookie(res, issued.cookie);
    appendCookie(res, issued.deviceCookie);
    appendCookie(res, csrf.cookie);

    return { csrfToken: csrf.token };
  }

  /**
   * The CSRF token for the request's session or pre-session, for a client
   * that cannot read the `csrf` cookie: call it from a `@Public()` GET route
   * (such as `GET /csrf-token`) and return the result. It is exactly the
   * token `CsrfMiddleware` set or kept as the cookie on this response,
   * minting the pre-session and the cookie when missing, as on any safe
   * request. The response is marked `Cache-Control: no-store`. Throws an
   * `AuthConfigError` on a request the middleware handed no token: an exempt
   * path (which mints nothing) or an unsafe method.
   */
  csrfToken(request: unknown, response: unknown): { csrfToken: string } {
    const token = handedCsrfToken(rawRequest(request));

    if (token === undefined) {
      throw new AuthConfigError(
        'SessionCookies.csrfToken needs a safe request (GET) that CsrfMiddleware checked: ' +
          'the route is on an exempt path or was called with an unsafe method.',
      );
    }

    rawResponse(response).setHeader('cache-control', 'no-store');

    return { csrfToken: token };
  }

  /**
   * Signs the request's session out through the core (`auth.logout`), clears
   * its cookie, and starts a fresh pre-session with a CSRF token bound to it.
   */
  async signOut(request: unknown, response: unknown): Promise<{ csrfToken: string }> {
    const req = rawRequest(request);
    const res = rawResponse(response);
    const principal = principalOf(req);

    const token = principal
      ? principal.token
      : this.options.auth.readSessionToken(req.headers.cookie);

    const meta = principal?.meta ?? requestMeta(req, this.options);
    const { cookie } = await this.options.auth.logout({ token, meta });
    const sameSite = sameSiteFor(req, this.options);
    const fresh = newPreSession(this.options, sameSite);
    const csrf = csrfCookie(this.options, preSessionBinding(fresh.id), sameSite);

    appendCookie(res, cookie);
    appendCookie(res, fresh.cookie);
    appendCookie(res, csrf.cookie);

    return { csrfToken: csrf.token };
  }
}
