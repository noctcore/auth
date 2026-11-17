// The pieces on their own: boot-time option checks, the trust-proxy setup, the
// request helpers under a Fastify-shaped request, the middleware's failure
// path and the guard outside HTTP.
import 'reflect-metadata';
import type { ExecutionContext, INestApplication } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthConfigError } from '@noctcore/auth';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { authMeta, currentSession, currentUser } from '../src/decorators';
import { CsrfMiddleware } from '../src/csrf.middleware';
import { resolveOptions, type AuthModuleOptions } from '../src/options';
import { appendCookie, header, rawRequest, rawResponse, type RawResponse } from '../src/request';
import { SessionCookies } from '../src/session-cookies';
import { SessionGuard } from '../src/session.guard';
import { configureTrustProxy, trustedHopsFromEnv } from '../src';
import { boot, CSRF_SECRET, makeAuth, ORIGIN, type Booted } from './support';

function options(overrides: Partial<AuthModuleOptions> = {}): AuthModuleOptions {
  return {
    auth: makeAuth().auth,
    trustedHops: 0,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    ...overrides,
  };
}

class FakeResponse implements RawResponse {
  statusCode = 200;
  body: string | undefined;
  readonly headers = new Map<string, number | string | readonly string[]>();

  getHeader(name: string) {
    return this.headers.get(name) as number | string | string[] | undefined;
  }

  setHeader(name: string, value: number | string | readonly string[]) {
    this.headers.set(name, value);
  }

  end(body?: string) {
    this.body = body;
  }
}

describe('resolveOptions', () => {
  it('refuses a missing auth instance', () => {
    expect(() => resolveOptions(options({ auth: undefined as never }))).toThrow(AuthConfigError);
  });

  it('refuses a hop count that is not a whole number of proxies', () => {
    for (const trustedHops of [-1, 1.5, Number.NaN]) {
      expect(() => resolveOptions(options({ trustedHops }))).toThrow(AuthConfigError);
    }
  });

  it('refuses no secrets, a short secret and no allowed origins', () => {
    const csrf = { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] };

    expect(() => resolveOptions(options({ csrf: { ...csrf, secrets: [] } }))).toThrow(
      AuthConfigError,
    );

    expect(() => resolveOptions(options({ csrf: { ...csrf, secrets: ['short'] } }))).toThrow(
      AuthConfigError,
    );

    expect(() => resolveOptions(options({ csrf: { ...csrf, allowedOrigins: [] } }))).toThrow(
      AuthConfigError,
    );
  });

  it('refuses a header name that is not a plain token', () => {
    expect(() =>
      resolveOptions(
        options({ csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], headerName: 'x y' } }),
      ),
    ).toThrow(AuthConfigError);
  });

  it('takes secrets as bytes, and names the cookies __Host- when the session cookie is', () => {
    const secure = { ...makeAuth().auth, cookieName: '__Host-session' };

    const resolved = resolveOptions(
      options({
        auth: secure,
        csrf: {
          secrets: [new TextEncoder().encode(CSRF_SECRET)],
          allowedOrigins: [ORIGIN],
          headerName: 'X-Token',
          allowSameSite: true,
        },
      }),
    );

    expect(resolved.secure).toBe(true);

    expect(resolved.csrf).toMatchObject({
      cookieName: '__Host-csrf',
      preSessionCookieName: '__Host-presession',
      headerName: 'x-token',
      allowSameSite: true,
      exempt: [],
    });
  });
});

describe('trustedHopsFromEnv', () => {
  it('reads a hop count, and treats unset as 0 outside production', () => {
    expect(trustedHopsFromEnv({ TRUST_PROXY: '2' })).toBe(2);
    expect(trustedHopsFromEnv({ TRUST_PROXY: 'false', NODE_ENV: 'production' })).toBe(0);
    expect(trustedHopsFromEnv({})).toBe(0);
    expect(trustedHopsFromEnv({ TRUST_PROXY: ' ', NODE_ENV: 'development' })).toBe(0);
  });

  it('refuses to start in production without TRUST_PROXY', () => {
    expect(() => trustedHopsFromEnv({ NODE_ENV: 'production' })).toThrow(/must be set/u);

    expect(() => trustedHopsFromEnv({ NODE_ENV: 'production', TRUST_PROXY: '' })).toThrow(
      AuthConfigError,
    );
  });

  it('refuses "true" and anything that is not a hop count', () => {
    expect(() => trustedHopsFromEnv({ TRUST_PROXY: 'true' })).toThrow(AuthConfigError);
    expect(() => trustedHopsFromEnv({ TRUST_PROXY: 'loopback' })).toThrow(/number of proxy hops/u);
  });
});

describe('configureTrustProxy', () => {
  it('sets the same hop count on Express and returns it', () => {
    const set = vi.fn();
    const app = { getHttpAdapter: () => ({ getInstance: () => ({ set }) }) };

    expect(configureTrustProxy(app as unknown as INestApplication, { TRUST_PROXY: '1' })).toBe(1);
    expect(set).toHaveBeenCalledWith('trust proxy', 1);
  });

  it('refuses an adapter without Express settings', () => {
    const app = { getHttpAdapter: () => ({ getInstance: () => ({}) }) };

    expect(() => configureTrustProxy(app as unknown as INestApplication, {})).toThrow(
      /Express adapter/u,
    );
  });
});

describe('request helpers', () => {
  it('unwraps a Fastify-style request and reply to the raw Node objects', () => {
    const raw = { headers: { cookie: 'a=1' } };
    const res = new FakeResponse();

    expect(rawRequest({ raw })).toBe(raw);
    expect(rawResponse({ raw: res })).toBe(res);
  });

  it('reads the first value of a repeated header', () => {
    expect(header({ headers: { 'x-a': ['one', 'two'] } }, 'x-a')).toBe('one');
  });

  it('keeps a Set-Cookie header that was set as one string', () => {
    const res = new FakeResponse();

    res.setHeader('set-cookie', 'a=1');

    appendCookie(res, {
      name: 'b',
      value: '2',
      attributes: { httpOnly: true, secure: false, sameSite: 'lax', path: '/' },
    });

    expect(res.getHeader('set-cookie')).toEqual(['a=1', 'b=2; Path=/; HttpOnly; SameSite=Lax']);
  });
});

describe('parameter decorators without the guard', () => {
  it('answer null, never a stale principal, for a request the guard did not see', () => {
    const context = {
      switchToHttp: () => ({ getRequest: () => ({ headers: {} }) }),
    } as unknown as ExecutionContext;

    expect(currentUser(undefined, context)).toBeNull();
    expect(currentSession(undefined, context)).toBeNull();
    expect(authMeta(undefined, context)).toBeUndefined();
  });
});

describe('CsrfMiddleware', () => {
  it('answers 500 with a fixed body, and logs only the error name, when the store fails', async () => {
    const { auth } = makeAuth();
    const error = vi.fn();

    const failing = {
      ...auth,
      validateRequest: () => Promise.reject(new TypeError('s:secret-session-id unreachable')),
      context: { ...auth.context, logger: { error, warn: vi.fn() } },
    };

    const middleware = new CsrfMiddleware(resolveOptions(options({ auth: failing })));
    const res = new FakeResponse();
    const next = vi.fn();

    await middleware.use(
      { method: 'GET', url: '/x', headers: { cookie: `${auth.cookieName}=token` } },
      res,
      next,
    );

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(500);
    expect(res.body).toBe('{"error":{"code":"internal"}}');
    expect(error).toHaveBeenCalledWith(expect.any(String), { error: 'TypeError' });
    expect(JSON.stringify(error.mock.calls)).not.toContain('secret-session-id');
  });

  it('logs the type of a thrown value that is not an Error', async () => {
    const { auth } = makeAuth();
    const error = vi.fn();

    const failing = {
      ...auth,
      readSessionToken: () => {
        const notAnError: unknown = 'boom';

        throw notAnError;
      },
      context: { ...auth.context, logger: { error, warn: vi.fn() } },
    };

    const res = new FakeResponse();

    await new CsrfMiddleware(resolveOptions(options({ auth: failing }))).use(
      { headers: {} },
      res,
      vi.fn(),
    );

    expect(res.statusCode).toBe(500);
    expect(error).toHaveBeenCalledWith(expect.any(String), { error: 'string' });
  });

  it('skips a path matched by an exempt RegExp, and reads the path without its query', async () => {
    const middleware = new CsrfMiddleware(
      resolveOptions(
        options({
          csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], exempt: [/^\/hooks\//u] },
        }),
      ),
    );

    const res = new FakeResponse();
    const next = vi.fn();

    await middleware.use({ method: 'POST', url: '/hooks/stripe?x=1', headers: {} }, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(res.headers.size).toBe(0);
  });

  it('treats a request without a method or URL as a GET of /', async () => {
    const res = new FakeResponse();
    const next = vi.fn();

    await new CsrfMiddleware(resolveOptions(options())).use({ headers: {} }, res, next);

    expect(next).toHaveBeenCalledWith();
  });
});

describe('SessionGuard outside HTTP', () => {
  it('leaves other transports to the app', async () => {
    const guard = new SessionGuard(new Reflector(), resolveOptions(options()));
    const context = { getType: () => 'rpc' } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });
});

describe('SessionCookies.signOut without the guard', () => {
  let t: Booted;

  afterEach(async () => {
    await t.app.close();
  });

  it('reads the token and the request meta itself', async () => {
    t = await boot();
    const cookies = t.app.get(SessionCookies);
    const logout = vi.spyOn(t.auth, 'logout');
    const res = new FakeResponse();

    await cookies.signOut({ headers: { cookie: 'session=abc' }, socket: {} }, res);

    expect(logout).toHaveBeenCalledWith({
      token: 'abc',
      meta: { ip: 'unknown', userAgent: '' },
    });

    expect(res.getHeader('set-cookie')).toHaveLength(3);
  });
});
