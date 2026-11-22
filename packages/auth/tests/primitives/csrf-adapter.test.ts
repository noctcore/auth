import { describe, expect, it } from 'vitest';

import { serializeCookie } from '../../src/http/cookie';
import { createCsrfToken, isSafeMethod, verifyCsrfToken } from '../../src/http/csrf';
import {
  appendSetCookie,
  bindCsrfToSession,
  csrfRequestAllowed,
  handOutCsrfToken,
  readCsrfCookies,
  resolveCsrfSettings,
  startCsrfPreSession,
  type CsrfContext,
  type SetCookieTarget,
} from '../../src/http/csrf-adapter';
import { AuthConfigError } from '../../src/shared/errors';
import {
  buildRequest,
  CSRF_CASES,
  CURRENT_SECRET,
  expectedOutcome,
  outcome,
  PARITY_CONFIGS,
  PARITY_ORIGIN,
  PARITY_SECRETS,
  PREVIOUS_SECRET,
  type Observed,
} from '../adapters/csrf-cases';

const encoder = new TextEncoder();

const context = (secure = false): CsrfContext => ({
  secure,
  csrf: resolveCsrfSettings({ secrets: PARITY_SECRETS, allowedOrigins: [PARITY_ORIGIN] }, secure),
});

describe('resolveCsrfSettings', () => {
  const base = { secrets: [CURRENT_SECRET], allowedOrigins: [PARITY_ORIGIN] };

  it('fills the defaults and names the cookies after the session cookie', () => {
    const plain = resolveCsrfSettings(base, false);

    expect(plain).toEqual({
      secrets: [encoder.encode(CURRENT_SECRET)],
      allowedOrigins: [PARITY_ORIGIN],
      crossSiteOrigins: [],
      allowSameSite: false,
      headerName: 'x-csrf-token',
      cookieName: 'csrf',
      preSessionCookieName: 'presession',
    });

    const secure = resolveCsrfSettings(base, true);

    expect([secure.cookieName, secure.preSessionCookieName]).toEqual([
      '__Host-csrf',
      '__Host-presession',
    ]);
  });

  it('keeps byte secrets, lower-cases the header and adds the cross-site origins to the allowlist', () => {
    const bytes = encoder.encode(PREVIOUS_SECRET);

    const settings = resolveCsrfSettings(
      {
        secrets: [bytes],
        allowedOrigins: [],
        crossSiteOrigins: ['app://desktop'],
        allowSameSite: true,
        headerName: 'X-My-Token',
      },
      false,
    );

    expect(settings.secrets[0]).toBe(bytes);
    expect(settings.allowedOrigins).toEqual(['app://desktop']);
    expect(settings.crossSiteOrigins).toEqual(['app://desktop']);
    expect(settings.allowSameSite).toBe(true);
    expect(settings.headerName).toBe('x-my-token');
  });

  it.each([
    [{ ...base, secrets: [] }, 'csrf.secrets needs at least one secret'],
    [{ ...base, allowedOrigins: [] }, 'csrf.allowedOrigins is empty'],
    [{ ...base, crossSiteOrigins: ['https://*.example'] }, 'csrf.crossSiteOrigins needs exact'],
    [{ ...base, secrets: ['short'] }, 'CSRF secrets must be at least 32 bytes'],
    [{ ...base, headerName: 'x csrf' }, 'Invalid CSRF header name: x csrf'],
  ])('refuses a bad option at boot (%#)', (input, message) => {
    expect(() => resolveCsrfSettings(input, false)).toThrow(AuthConfigError);
    expect(() => resolveCsrfSettings(input, false)).toThrow(message);
  });
});

describe('isSafeMethod', () => {
  it('passes GET, HEAD and OPTIONS in any ASCII case, and nothing else', () => {
    for (const method of ['GET', 'get', 'Head', 'options']) expect(isSafeMethod(method)).toBe(true);

    // The second one ends in a long s, which toUpperCase() would fold into "S".
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONſ', 'TRACE']) {
      expect(isSafeMethod(method)).toBe(false);
    }
  });
});

describe('readCsrfCookies', () => {
  const { csrf } = context();

  it('reads both cookies and drops a pre-session id we could not have minted', () => {
    const id = 'a'.repeat(32);

    expect(readCsrfCookies(csrf, `presession=${id}; csrf=tok`)).toEqual({
      preSession: id,
      token: 'tok',
    });

    expect(readCsrfCookies(csrf, 'presession=A'.padEnd(43, 'A'))).toEqual({
      preSession: null,
      token: undefined,
    });

    expect(readCsrfCookies(csrf, undefined)).toEqual({ preSession: null, token: undefined });
  });
});

describe('the cookies the layer sets', () => {
  it('binds a token to a session, readable by the page and on the given SameSite', () => {
    const ctx = context(true);
    const { token, cookie } = bindCsrfToSession(ctx, { id: 's1' }, 'none');

    expect(cookie).toEqual({
      name: '__Host-csrf',
      value: token,
      attributes: { httpOnly: false, secure: true, sameSite: 'none', path: '/' },
    });

    const check = (binding: string): boolean =>
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding,
        secrets: ctx.csrf.secrets,
      });

    expect(check('session:s1')).toBe(true);
    expect(check('session:s2')).toBe(false);
  });

  it('starts a pre-session: an HttpOnly 32 hex character id, then a token bound to it', () => {
    const { token, cookies } = startCsrfPreSession(context(), 'strict');
    const [pre, csrf] = cookies;

    expect(cookies).toHaveLength(2);
    expect(pre?.name).toBe('presession');
    expect(pre?.value).toMatch(/^[0-9a-f]{32}$/u);

    expect(pre?.attributes).toEqual({
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      path: '/',
    });

    expect(csrf?.value).toBe(token);

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding: `pre:${pre?.value}`,
        secrets: [encoder.encode(CURRENT_SECRET)],
      }),
    ).toBe(true);
  });

  it('signs a new token with the current secret only', () => {
    const { token } = bindCsrfToSession(context(), { id: 's1' }, 'lax');

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding: 'session:s1',
        secrets: [encoder.encode(PREVIOUS_SECRET)],
      }),
    ).toBe(false);
  });
});

describe('handOutCsrfToken', () => {
  it('takes the SameSite it is given for both cookies', () => {
    const handout = handOutCsrfToken(context(), {
      session: null,
      cookies: { preSession: null, token: undefined },
      sameSite: 'none',
    });

    expect(handout.cookies.map((cookie) => cookie.attributes.sameSite)).toEqual(['none', 'none']);
    expect(handout.cookies[1]?.value).toBe(handout.token);
  });
});

describe('csrfRequestAllowed', () => {
  it('lets a listed cross-site origin through and same-site only when allowed', () => {
    const csrf = resolveCsrfSettings(
      {
        secrets: [CURRENT_SECRET],
        allowedOrigins: [PARITY_ORIGIN],
        crossSiteOrigins: ['app://desktop'],
        allowSameSite: true,
      },
      false,
    );

    const token = createCsrfToken(encoder.encode(CURRENT_SECRET), 'session:s1');

    const verdict = (origin: string, secFetchSite: string): boolean =>
      csrfRequestAllowed(csrf, {
        session: { id: 's1' },
        cookies: { preSession: null, token },
        origin,
        secFetchSite,
        headerToken: token,
      });

    expect(verdict('app://desktop', 'cross-site')).toBe(true);
    expect(verdict(PARITY_ORIGIN, 'cross-site')).toBe(false);
    expect(verdict(PARITY_ORIGIN, 'same-site')).toBe(true);
  });
});

describe('appendSetCookie', () => {
  const target = (initial: number | string | string[] | undefined) => {
    let value = initial;

    const res: SetCookieTarget & { readonly value: unknown } = {
      getHeader: () => value,
      setHeader: (_name, next) => {
        value = next;
      },
      get value() {
        return value;
      },
    };

    return res;
  };

  const spec = {
    name: 'a',
    value: '1',
    attributes: { httpOnly: true, secure: false, sameSite: 'lax', path: '/' },
  } as const;

  it('keeps the cookies already set, whether none, one string or a list', () => {
    for (const [initial, before] of [
      [undefined, []],
      ['x=1', ['x=1']],
      [
        ['x=1', 'y=2'],
        ['x=1', 'y=2'],
      ],
    ] as const) {
      const res = target(initial as string | string[] | undefined);

      appendSetCookie(res, spec);

      expect(res.value).toEqual([...before, serializeCookie(spec)]);
    }
  });
});

// The shared table, run against the core's functions themselves; the
// adapters run the same table against their real entry points.
describe('the CSRF table every adapter answers', () => {
  const session = { id: 'session-id', cookie: 'session=unused' };

  it.each(CSRF_CASES.map((row) => [row.name, row] as const))('%s', (_name, row) => {
    const request = buildRequest(row, session);
    const ctx = { secure: false, csrf: resolveCsrfSettings(PARITY_CONFIGS[request.config], false) };
    const cookies = readCsrfCookies(ctx.csrf, request.headers['cookie']);
    const ref = row.signedIn ? { id: session.id } : null;
    let seen: Observed;

    if (isSafeMethod(request.method)) {
      const handout = handOutCsrfToken(ctx, { session: ref, cookies, sameSite: 'lax' });

      seen = { setCookies: handout.cookies.map((cookie) => cookie.name), token: handout.token };
    } else {
      seen = {
        allowed: csrfRequestAllowed(ctx.csrf, {
          session: ref,
          cookies,
          origin: request.headers['origin'],
          secFetchSite: request.headers['sec-fetch-site'],
          headerToken: request.headers[ctx.csrf.headerName],
        }),
      };
    }

    expect(outcome(request, seen)).toEqual(expectedOutcome(row));
  });
});
