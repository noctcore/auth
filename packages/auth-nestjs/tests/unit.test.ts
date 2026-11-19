// The pieces on their own: boot-time option checks, the trust-proxy setup, the
// request helpers under a Fastify-shaped request, the middleware's failure
// path and the guard outside HTTP.
import 'reflect-metadata';
import type { ExecutionContext, INestApplication } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  adoptLegacySessions,
  AuthConfigError,
  createAuth,
  generateToken,
  resolveSameSite,
  sha256Hex,
  type LegacySession,
  type SessionCookieConfig,
  type SessionStore,
} from '@noctcore/auth';
import { manualClock, memoryStores, plainHasher, recordingMailer } from '@noctcore/auth/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { authMeta, currentSession, currentUser } from '../src/decorators';
import { CsrfMiddleware } from '../src/csrf.middleware';
import { resolveOptions, type AuthModuleOptions } from '../src/options';
import {
  appendCookie,
  header,
  rawRequest,
  rawResponse,
  requestMeta,
  type RawResponse,
} from '../src/request';
import { SessionCookies } from '../src/session-cookies';
import { SessionGuard } from '../src/session.guard';
import {
  configureTrustProxy,
  Public,
  RequireFreshAuth,
  RequireRole,
  trustedHopsFromEnv,
} from '../src';
import { boot, Browser, CSRF_SECRET, makeAuth, ORIGIN, type Booted } from './support';

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
  it('waits 10 seconds for background work on shutdown unless told otherwise', () => {
    expect(resolveOptions(options()).shutdownTimeout).toBe('10s');
    expect(resolveOptions(options({ shutdownTimeout: '2s' })).shutdownTimeout).toBe('2s');
  });

  it('refuses a shutdown timeout that is not a duration longer than zero', () => {
    for (const shutdownTimeout of ['0s', 0, -1, 'soon', Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => resolveOptions(options({ shutdownTimeout: shutdownTimeout as never }))).toThrow(
        AuthConfigError,
      );
    }

    expect(resolveOptions(options({ shutdownTimeout: 1 })).shutdownTimeout).toBe(1);
  });

  it('refuses a missing auth instance', () => {
    expect(() => resolveOptions(options({ auth: undefined as never }))).toThrow(AuthConfigError);
  });

  it('refuses a hop count that is not a whole number of proxies', () => {
    for (const trustedHops of [-1, 1.5, Number.NaN, 17, Number.MAX_SAFE_INTEGER + 2]) {
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

  it('falls back to Lax cookies for a stand-in auth with no cookie config', () => {
    const real = makeAuth().auth;
    const { cookie, ...context } = real.context;
    const standIn = { ...real, context };

    expect(cookie).toEqual({ secure: false });
    const resolved = resolveOptions(options({ auth: standIn }));

    expect(resolved.cookie).toEqual({ secure: false });
  });

  it('refuses SameSite=None when the adapter cookies are not Secure, whatever the config claims', () => {
    const real = makeAuth().auth;

    const claims = (sameSite: NonNullable<SessionCookieConfig['sameSite']>) => ({
      ...real,
      context: { ...real.context, cookie: { secure: true, sameSite } },
    });

    expect(() => resolveOptions(options({ auth: claims('none') }))).toThrow(AuthConfigError);

    const resolved = resolveOptions(options({ auth: claims(() => 'none') }));

    expect(resolved.cookie.secure).toBe(false);
    expect(() => resolveSameSite(resolved.cookie, 'app://desktop')).toThrow(AuthConfigError);
  });

  it('accepts a desktop-only allowlist, with crossSiteOrigins and no allowedOrigins', () => {
    const resolved = resolveOptions(
      options({
        csrf: { secrets: [CSRF_SECRET], allowedOrigins: [], crossSiteOrigins: ['app://desktop'] },
      }),
    );

    expect(resolved.csrf.allowedOrigins).toEqual(['app://desktop']);
    expect(resolved.csrf.crossSiteOrigins).toEqual(['app://desktop']);
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

  it('accepts up to 16 hops and refuses more, or a count past the safe integers', () => {
    expect(trustedHopsFromEnv({ TRUST_PROXY: '16' })).toBe(16);
    expect(() => trustedHopsFromEnv({ TRUST_PROXY: '17' })).toThrow(/from 0 to 16/u);

    expect(() => trustedHopsFromEnv({ TRUST_PROXY: '99999999999999999999' })).toThrow(
      AuthConfigError,
    );
  });

  it('refuses "true", unknown names and malformed ranges', () => {
    for (const bad of ['true', 'localhost', 'loopback, nope', '10.0.0.0/33', '1, loopback'])
      expect(() => trustedHopsFromEnv({ TRUST_PROXY: bad }), bad).toThrow(AuthConfigError);
  });

  it('expands each Express preset to the ranges Express uses', () => {
    expect(trustedHopsFromEnv({ TRUST_PROXY: 'loopback' })).toEqual(['127.0.0.1/8', '::1/128']);

    expect(trustedHopsFromEnv({ TRUST_PROXY: 'linklocal' })).toEqual([
      '169.254.0.0/16',
      'fe80::/10',
    ]);

    expect(trustedHopsFromEnv({ TRUST_PROXY: 'uniquelocal' })).toEqual([
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      'fc00::/7',
    ]);
  });

  it('mixes presets with explicit addresses and CIDR ranges', () => {
    expect(
      trustedHopsFromEnv({
        TRUST_PROXY: 'loopback, 203.0.113.0/24, 2001:db8::/32, 198.51.100.9',
        NODE_ENV: 'production',
      }),
    ).toEqual(['127.0.0.1/8', '::1/128', '203.0.113.0/24', '2001:db8::/32', '198.51.100.9']);
  });
});

describe('configureTrustProxy', () => {
  it('sets the same hop count on Express and returns it', () => {
    const set = vi.fn();
    const app = { getHttpAdapter: () => ({ getInstance: () => ({ set }) }) };

    expect(configureTrustProxy(app as unknown as INestApplication, { TRUST_PROXY: '1' })).toBe(1);
    expect(set).toHaveBeenCalledWith('trust proxy', 1);
  });

  it('sets the same address list on Express and returns it', () => {
    const set = vi.fn();
    const app = { getHttpAdapter: () => ({ getInstance: () => ({ set }) }) };

    expect(
      configureTrustProxy(app as unknown as INestApplication, {
        TRUST_PROXY: 'loopback, 10.0.0.0/8',
      }),
    ).toEqual(['127.0.0.1/8', '::1/128', '10.0.0.0/8']);

    expect(set).toHaveBeenCalledWith('trust proxy', ['127.0.0.1/8', '::1/128', '10.0.0.0/8']);
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

/** A handler and class carrying the given decorators, and a context for them. */
function contextFor(
  type: string,
  decorate: { handler?: MethodDecorator[]; controller?: ClassDecorator[] } = {},
  request: object = { method: 'GET', headers: {} },
): ExecutionContext {
  class Target {
    handle() {
      return undefined;
    }
  }

  for (const decorator of decorate.controller ?? []) decorator(Target);

  const descriptor = Object.getOwnPropertyDescriptor(
    Target.prototype,
    'handle',
  ) as PropertyDescriptor;

  for (const decorator of decorate.handler ?? []) decorator(Target.prototype, 'handle', descriptor);

  return {
    getType: () => type,
    getHandler: () => Target.prototype.handle,
    getClass: () => Target,
    switchToHttp: () => ({ getRequest: () => request, getResponse: () => ({}) }),
  } as unknown as ExecutionContext;
}

describe('SessionGuard outside HTTP', () => {
  const guard = () => new SessionGuard(new Reflector(), resolveOptions(options()));

  it('refuses a GraphQL, WebSocket or microservice handler that is not public', async () => {
    for (const type of ['rpc', 'ws', 'graphql']) {
      await expect(guard().canActivate(contextFor(type))).resolves.toBe(false);
    }
  });

  it('lets a public one through, unless it also asks for a role or fresh auth', async () => {
    await expect(guard().canActivate(contextFor('rpc', { handler: [Public()] }))).resolves.toBe(
      true,
    );

    await expect(
      guard().canActivate(
        contextFor('graphql', { controller: [Public()], handler: [RequireRole('admin')] }),
      ),
    ).resolves.toBe(false);

    await expect(
      guard().canActivate(contextFor('ws', { handler: [Public(), RequireFreshAuth()] })),
    ).resolves.toBe(false);
  });
});

describe('SessionGuard on HTTP, without the module around it', () => {
  it('refuses an unsafe request the CSRF middleware never saw, even on a public route', async () => {
    const guard = new SessionGuard(new Reflector(), resolveOptions(options()));
    const context = contextFor('http', { handler: [Public()] }, { method: 'POST', headers: {} });

    await expect(guard.canActivate(context)).rejects.toMatchObject({
      status: 403,
      response: { error: { code: 'forbidden' } },
    });
  });

  it('never lets @Public() skip a role check it carries, and has no roles to give without the option', async () => {
    const guard = new SessionGuard(new Reflector(), resolveOptions(options()));

    const context = contextFor('http', {
      controller: [Public()],
      handler: [RequireRole('admin')],
    });

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 401 });
  });

  it('answers 403, not 500, when a role is required and there is no roles function', async () => {
    const { auth } = makeAuth();

    await auth.register({
      email: 'c@example.com',
      password: 'correct horse battery',
      meta: { ip: '192.0.2.1' },
    });

    const login = await auth.login({
      email: 'c@example.com',
      password: 'correct horse battery',
      meta: { ip: '192.0.2.1' },
    });

    const token = login.ok && login.value.kind === 'session' ? login.value.session.token : '';

    expect(token).not.toBe('');

    const guard = new SessionGuard(new Reflector(), resolveOptions(options({ auth })));

    const context = contextFor(
      'http',
      { handler: [RequireRole('admin')] },
      {
        method: 'GET',
        headers: { cookie: `${auth.cookieName}=${token}` },
      },
    );

    await expect(guard.canActivate(context)).rejects.toMatchObject({
      status: 403,
      response: { error: { code: 'forbidden' } },
    });
  });

  it('answers a fixed 500 and logs only the error name when the store fails', async () => {
    const { auth } = makeAuth();
    const error = vi.fn();

    const failing = {
      ...auth,
      validateRequest: () => Promise.reject(new RangeError('s:secret-session-id gone')),
      context: { ...auth.context, logger: { error, warn: vi.fn() } },
    };

    const guard = new SessionGuard(new Reflector(), resolveOptions(options({ auth: failing })));
    // No method at all reads as a GET.
    const context = contextFor('http', {}, { headers: { cookie: `${auth.cookieName}=t` } });

    await expect(guard.canActivate(context)).rejects.toMatchObject({
      status: 500,
      response: { error: { code: 'internal' } },
    });

    expect(error).toHaveBeenCalledWith(expect.any(String), { error: 'RangeError' });
    expect(JSON.stringify(error.mock.calls)).not.toContain('secret-session-id');
  });

  it('logs the type of a thrown value that is not an Error', async () => {
    const { auth } = makeAuth();
    const error = vi.fn();

    const failing = {
      ...auth,
      readSessionToken: () => {
        const notAnError: unknown = 42;

        throw notAnError;
      },
      context: { ...auth.context, logger: { error, warn: vi.fn() } },
    };

    const guard = new SessionGuard(new Reflector(), resolveOptions(options({ auth: failing })));

    await expect(guard.canActivate(contextFor('http'))).rejects.toMatchObject({ status: 500 });
    expect(error).toHaveBeenCalledWith(expect.any(String), { error: 'number' });
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

describe('trusted proxies by address and the client IP header', () => {
  let t: Booted | undefined;

  afterEach(async () => {
    await t?.app.close();
    t = undefined;
  });

  const peer = (remoteAddress: string, headers: Record<string, string> = {}) => ({
    headers,
    socket: { remoteAddress },
  });

  it('checks both settings at boot', () => {
    const resolved = resolveOptions(
      options({ trustedHops: ['loopback'], clientIpHeader: 'CF-Connecting-IP' }),
    );

    expect(resolved.trustedHops).toEqual(['127.0.0.1/8', '::1/128']);
    expect(resolved.clientIpHeader).toBe('cf-connecting-ip');
    expect(resolveOptions(options()).clientIpHeader).toBeUndefined();

    expect(() => resolveOptions(options({ trustedHops: ['localhost'] }))).toThrow(AuthConfigError);

    expect(() =>
      resolveOptions(options({ trustedHops: ['loopback'], clientIpHeader: 'x-forwarded-for' })),
    ).toThrow(AuthConfigError);

    // A hop count never checks the socket, so a direct client could set the header.
    expect(() =>
      resolveOptions(options({ trustedHops: 1, clientIpHeader: 'cf-connecting-ip' })),
    ).toThrow(/list of your edge/u);
  });

  it('reads the header through a trusted hop and ignores it from any other peer', () => {
    const trust = resolveOptions(
      options({ trustedHops: ['10.0.0.0/8'], clientIpHeader: 'cf-connecting-ip' }),
    );

    expect(requestMeta(peer('10.0.0.2', { 'cf-connecting-ip': '198.51.100.7' }), trust).ip).toBe(
      '198.51.100.7',
    );

    expect(
      requestMeta(peer('203.0.113.50', { 'cf-connecting-ip': '198.51.100.7' }), trust).ip,
    ).toBe('203.0.113.50');

    expect(
      requestMeta(
        peer('10.0.0.2', { 'cf-connecting-ip': 'garbage', 'x-forwarded-for': '203.0.113.9' }),
        trust,
      ).ip,
    ).toBe('203.0.113.9');
  });

  it('serves the header IP to the flows when the test client is a trusted proxy', async () => {
    t = await boot({ options: { trustedHops: ['loopback'], clientIpHeader: 'cf-connecting-ip' } });
    const browser = new Browser(t.app, '203.0.113.50');

    await browser.signIn();

    const meta = await browser.send('GET', '/api/meta', undefined, {
      'cf-connecting-ip': '198.51.100.7',
    });

    expect(meta.body['ip']).toBe('198.51.100.7');
  });

  it('ignores the header when the test client is not a trusted proxy', async () => {
    t = await boot({
      options: { trustedHops: ['10.0.0.0/8'], clientIpHeader: 'cf-connecting-ip' },
    });

    const browser = new Browser(t.app, '203.0.113.50');

    await browser.signIn();

    const ip = (
      await browser.send('GET', '/api/meta', undefined, { 'cf-connecting-ip': '198.51.100.7' })
    ).body['ip'];

    expect(String(ip)).toMatch(/127\.0\.0\.1|::1/u);
  });
});

/**
 * Two app instances over shared stores behind `adoptLegacySessions`, as two
 * processes would be, with a session store whose writes land 300 ms later
 * (a slow database), longer than the wrapper's wait for a racing request.
 */
function racingInstances() {
  const clock = manualClock();
  const stores = memoryStores(clock);
  const rows = new Map<string, LegacySession>();

  const take = async (id: string) => {
    const row = rows.get(id) ?? null;

    rows.delete(id);

    return row;
  };

  const slow: SessionStore = {
    create: async (session, ttlMs) => {
      await new Promise<void>((resolve) => setTimeout(resolve, 300));
      await stores.sessions.create(session, ttlMs);
    },
    get: (id) => stores.sessions.get(id),
    touch: (session) => stores.sessions.touch(session),
    delete: (userId, ids) => stores.sessions.delete(userId, ids),
    listByUser: (userId) => stores.sessions.listByUser(userId),
    getEpoch: (userId) => stores.sessions.getEpoch(userId),
    bumpEpoch: (userId) => stores.sessions.bumpEpoch(userId),
  };

  const instance = () =>
    createAuth({
      stores: { ...stores, sessions: adoptLegacySessions(slow, { take, maxTtl: '30d', clock }) },
      clock,
      password: { hasher: plainHasher(), breachCheck: false },
      secret: 'auth-secret-that-is-at-least-32-bytes-long',
      urls: { resetPassword: (token) => `${ORIGIN}/reset#${token}` },
      mailer: recordingMailer(),
    });

  /** A legacy row for a new cookie token; `expired` makes it one the wrapper drops. */
  const legacyToken = (expired = false) => {
    const token = generateToken();
    const now = clock.now();

    rows.set(sha256Hex(token), {
      userId: 'user-1',
      createdAt: now - 60_000,
      authenticatedAt: now - 60_000,
      lastActiveAt: now - 60_000,
      expiresAt: expired ? now : now + 86_400_000,
      idleTimeoutMs: 86_400_000,
      rememberMe: true,
    });

    return token;
  };

  return { first: instance(), second: instance(), legacyToken };
}

type RacingAuth = ReturnType<typeof racingInstances>['first'];

describe('a session another instance is still adopting', () => {
  async function get(auth: RacingAuth, token: string) {
    const res = new FakeResponse();
    const next = vi.fn();

    await new CsrfMiddleware(resolveOptions(options({ auth }))).use(
      { method: 'GET', url: '/x', headers: { cookie: `${auth.cookieName}=${token}` } },
      res,
      next,
    );

    expect(next).toHaveBeenCalledOnce();

    const cookies = (res.getHeader('set-cookie') ?? []) as string[];

    return cookies.some((line) => line.startsWith(`${auth.cookieName}=;`));
  }

  it('keeps the cookie of the request that lost the race, and clears a dead one', async () => {
    const { first, second, legacyToken } = racingInstances();
    const token = legacyToken();
    const validate = vi.spyOn(second, 'validateRequest');

    // The loser is refused (its wait is shorter than the winner's write) but keeps its cookie.
    const [wonCleared, lostCleared] = await Promise.all([get(first, token), get(second, token)]);

    expect(await validate.mock.results[0]?.value).toMatchObject({
      ok: false,
      reason: 'session_adopting',
    });

    expect(await second.validateRequest({ token })).toMatchObject({ ok: true });
    expect([wonCleared, lostCleared]).toEqual([false, false]);

    // A malformed token, and a legacy record the wrapper drops, still clear it.
    expect(await get(second, 'not-a-token')).toBe(true);
    expect(await get(second, legacyToken(true))).toBe(true);
  });
});
