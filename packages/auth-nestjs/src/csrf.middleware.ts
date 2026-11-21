/**
 * Cross-site request forgery, checked before any guard or handler runs.
 *
 * For every unsafe method on a route that is not exempt, all three of the
 * core's checks must pass: the `Origin` is on the allowlist
 * (`verifyRequestOrigin`), `Sec-Fetch-Site` says `same-origin` whenever the
 * browser sends it, or `cross-site` from an origin on `crossSiteOrigins`
 * (`verifyFetchSite`), and the double-submit token matches its cookie and is
 * bound to this session or pre-session (`verifyCsrfToken`). The cookies set
 * here take the session cookie's `SameSite` for the request's `Origin`.
 *
 * A refusal is answered here, with 403 and one fixed body, instead of
 * `next(err)`: an error handed on could reach a filter that echoes its
 * message, and the answer must not say which check failed.
 *
 * Safe methods skip the CSRF check but never the session check (that is the
 * guard's job). On a safe request the middleware hands out what the page
 * needs to make unsafe ones: a pre-session id when the browser has no session
 * and no id yet, and a CSRF cookie bound to the current binding. Both happen
 * only after the exempt check, so an exempt route never mints anything.
 *
 * Guide: Learn, "CSRF".
 */
import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import { parseCookieHeader, verifyFetchSite, verifyRequestOrigin } from '@noctcore/auth';
import {
  binding,
  isSafeMethod,
  csrfCookie,
  csrfTokenValid,
  newPreSession,
  preSessionBinding,
  readPreSession,
} from './csrf-tokens';
import type { ResolvedOptions } from './options';
import {
  appendCookie,
  blankSessionCookie,
  header,
  markCsrfPassed,
  pathOf,
  rawRequest,
  rawResponse,
  sameSiteFor,
  sessionState,
  type RawRequest,
  type RawResponse,
} from './request';
import { AUTH_OPTIONS } from './tokens';

const FORBIDDEN = JSON.stringify({ error: { code: 'forbidden' } });
const INTERNAL = JSON.stringify({ error: { code: 'internal' } });

function send(res: RawResponse, status: number, body: string): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(body);
}

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  constructor(@Inject(AUTH_OPTIONS) private readonly options: ResolvedOptions) {}

  async use(request: unknown, response: unknown, next: (error?: unknown) => void): Promise<void> {
    const req = rawRequest(request);
    const res = rawResponse(response);

    if (this.isExempt(pathOf(req))) {
      markCsrfPassed(req);

      return next();
    }

    try {
      if (!(await this.check(req, res))) return send(res, 403, FORBIDDEN);

      markCsrfPassed(req);
      next();
    } catch (error) {
      // Only the error's name: a store error can carry the session key.
      this.options.auth.context.logger.error('CSRF middleware could not check the request', {
        error: error instanceof Error ? error.name : typeof error,
      });

      send(res, 500, INTERNAL);
    }
  }

  private isExempt(path: string): boolean {
    return this.options.csrf.exempt.some((rule) =>
      typeof rule === 'string' ? rule === path : rule.test(path),
    );
  }

  /** True when the request may go on. Sets the cookies a safe request should carry back. */
  private async check(req: RawRequest, res: RawResponse): Promise<boolean> {
    const { csrf } = this.options;
    const method = req.method ?? 'GET';
    const state = await sessionState(req, this.options);
    const cookies = parseCookieHeader(header(req, 'cookie'));
    const preSession = readPreSession(cookies.get(csrf.preSessionCookieName));
    const cookieToken = cookies.get(csrf.cookieName);
    const origin = header(req, 'origin');
    // Every cookie set here travels with the session cookie, so takes its SameSite.
    const sameSite = sameSiteFor(req, this.options);

    // A token the core refused for good is cleared, so the browser stops
    // sending it. One another request may still be adopting is kept.
    if (state.clearCookie) appendCookie(res, blankSessionCookie(this.options, sameSite));

    if (!isSafeMethod(method)) {
      const secFetchSite = header(req, 'sec-fetch-site');

      const originOk = verifyRequestOrigin({
        method,
        origin,
        allowedOrigins: csrf.allowedOrigins,
      });

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

      const tokenOk = csrfTokenValid(this.options, {
        cookieToken,
        headerToken: header(req, csrf.headerName),
        bound: binding(state.session, preSession),
      });

      return originOk && siteOk && tokenOk;
    }

    let bound = binding(state.session, preSession);

    if (bound === null) {
      const fresh = newPreSession(this.options, sameSite);

      appendCookie(res, fresh.cookie);
      bound = preSessionBinding(fresh.id);
    }

    const current = csrfTokenValid(this.options, {
      cookieToken,
      headerToken: cookieToken,
      bound,
    });

    if (!current) appendCookie(res, csrfCookie(this.options, bound, sameSite).cookie);

    return true;
  }
}
