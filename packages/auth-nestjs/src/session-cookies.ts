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
 */
import { Inject, Injectable } from '@nestjs/common';
import type { IssuedSession } from '@noctcore/auth';
import { csrfCookie, newPreSession, preSessionBinding, sessionBinding } from './csrf-tokens';
import type { ResolvedOptions } from './options';
import { appendCookie, principalOf, rawRequest, rawResponse, requestMeta } from './request';
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
    const csrf = csrfCookie(this.options, sessionBinding(issued.session));

    appendCookie(res, issued.cookie);
    appendCookie(res, issued.deviceCookie);
    appendCookie(res, csrf.cookie);

    return { csrfToken: csrf.token };
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

    const meta = principal?.meta ?? requestMeta(req, this.options.trustedHops);
    const { cookie } = await this.options.auth.logout({ token, meta });
    const fresh = newPreSession(this.options);
    const csrf = csrfCookie(this.options, preSessionBinding(fresh.id));

    appendCookie(res, cookie);
    appendCookie(res, fresh.cookie);
    appendCookie(res, csrf.cookie);

    return { csrfToken: csrf.token };
  }
}
