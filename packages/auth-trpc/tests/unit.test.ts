// Unit tests: the boot checks, the request adapters, the error formatter, the
// middleware bodies alone, and the schema walker's corners.
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
import { initTRPC, TRPCError } from '@trpc/server';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  AuthedMiddleware,
  authErrorFormatter,
  createAuthContext,
  createAuthMiddlewares,
  CsrfMiddleware,
  MAX_TRUSTED_HOPS,
  RateLimitMiddleware,
  type AuthContextOptions,
  type AuthState,
  type AuthWriter,
  WritesCookiesMiddleware,
} from '../src';
import { isStreamedRequest } from '../src/context';
import { resolveOptions } from '../src/options';
import { secretKeys } from '../src/secret-queries';
import { CSRF_SECRET, EMAIL, makeAuth, ORIGIN, PASSWORD } from './support';

function options(overrides: Partial<AuthContextOptions> = {}): AuthContextOptions {
  return {
    auth: makeAuth().auth,
    trustedHops: 0,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    ...overrides,
  };
}

const csrf = (overrides: Partial<AuthContextOptions['csrf']>) => ({
  csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], ...overrides },
});

/**
 * A mutation context whose request passed the CSRF checks, as a page sends
 * it: a first visit hands out the pre-session and CSRF cookies, then a
 * same-origin POST carries them and echoes the token. `writesCookies` runs
 * the CSRF check itself, so a cookie writer needs one.
 */
async function trustedContext(headers: Record<string, string> = {}, resHeaders = new Headers()) {
  const authContext = createAuthContext(options());
  const visit = new Headers();

  await authContext.fetch({ req: new Request(ORIGIN), resHeaders: visit });

  const cookies = visit.getSetCookie().map((line) => line.split(';')[0] ?? '');
  const token = cookies.find((pair) => pair.startsWith('csrf='))?.slice('csrf='.length) ?? '';

  return authContext.fetch({
    req: new Request(ORIGIN, {
      method: 'POST',
      headers: {
        origin: ORIGIN,
        'sec-fetch-site': 'same-origin',
        'x-csrf-token': decodeURIComponent(token),
        cookie: cookies.join('; '),
        ...headers,
      },
    }),
    resHeaders,
  });
}

describe('createAuthContext boot checks', () => {
  it('refuses a missing auth, a bad hop count, and weak CSRF settings', () => {
    expect(() => createAuthContext(options({ auth: undefined as never }))).toThrow(AuthConfigError);

    for (const hops of [-1, 1.5, Number.NaN, MAX_TRUSTED_HOPS + 1, 2 ** 53]) {
      expect(() => createAuthContext(options({ trustedHops: hops }))).toThrow(/trustedHops/u);
    }

    expect(() => createAuthContext(options(csrf({ secrets: [] })))).toThrow(/at least one/u);
    expect(() => createAuthContext(options(csrf({ allowedOrigins: [] })))).toThrow(/empty/u);
    expect(() => createAuthContext(options(csrf({ secrets: ['short'] })))).toThrow();
    expect(() => createAuthContext(options(csrf({ headerName: 'x csrf' })))).toThrow(/header/u);
  });

  it('refuses CSRF options of the wrong type, as the environment gives them', () => {
    for (const [bad, message] of [
      [{ allowSameSite: 'false' }, 'csrf.allowSameSite must be true or false'],
      [{ allowSameSite: 1 }, 'csrf.allowSameSite must be true or false'],
      [{ secrets: CSRF_SECRET }, 'csrf.secrets must be a list'],
      [{ secrets: [undefined] }, 'csrf.secrets must hold strings or bytes'],
      [{ allowedOrigins: 'https://app.test' }, 'csrf.allowedOrigins must be a list'],
      [{ crossSiteOrigins: 'app://desktop' }, 'csrf.crossSiteOrigins must be a list'],
      [{ headerName: 42 }, 'csrf.headerName must be a string'],
    ] as const) {
      const create = () => createAuthContext(options(csrf(bad as never)));

      expect(create).toThrow(AuthConfigError);
      expect(create).toThrow(message);
    }

    for (const given of [{ allowSameSite: true }, { allowSameSite: false }, {}]) {
      expect(() => createAuthContext(options(csrf(given)))).not.toThrow();
    }
  });

  it('accepts byte secrets, a custom header, and the hop cap', () => {
    expect(() =>
      createAuthContext(
        options({
          trustedHops: MAX_TRUSTED_HOPS,
          ...csrf({ secrets: [new TextEncoder().encode(CSRF_SECRET)], headerName: 'X-Token' }),
        }),
      ),
    ).not.toThrow();
  });

  it('falls back to Lax cookies for a stand-in auth with no cookie config', () => {
    const real = makeAuth().auth;
    const { cookie, ...context } = real.context;
    const standIn = { ...real, context };

    expect(cookie).toEqual({ secure: false });

    expect(resolveOptions(options({ auth: standIn })).cookie).toEqual({ secure: false });
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

  it('names the CSRF cookies __Host- when the session cookie is secure', async () => {
    const clock = manualClock();

    const auth = createAuth({
      stores: memoryStores(clock),
      clock,
      password: { hasher: plainHasher(), breachCheck: false },
      secret: 'auth-secret-that-is-at-least-32-bytes-long',
      urls: { resetPassword: (token) => `${ORIGIN}/reset#${token}` },
      mailer: recordingMailer(),
    });

    const resHeaders = new Headers();

    await createAuthContext(options({ auth })).fetch({
      req: new Request(ORIGIN),
      resHeaders,
    });

    const names = resHeaders.getSetCookie().map((line) => line.split('=')[0]);

    expect(names).toEqual(['__Host-presession', '__Host-csrf']);
    expect(resHeaders.getSetCookie().every((line) => line.includes('Secure'))).toBe(true);
  });
});

describe('the request adapters', () => {
  it('reads a fetch request without a peer address as the unknown IP', async () => {
    const { auth } = await createAuthContext(options()).fetch({
      req: new Request(ORIGIN, { headers: { 'user-agent': 'ua' } }),
      resHeaders: new Headers(),
    });

    expect(auth.meta).toEqual({ ip: 'unknown', userAgent: 'ua' });
  });

  it('reads a Node request with repeated headers and keeps a cookie already set', async () => {
    const headers = new Map<string, unknown>([['set-cookie', 'theme=dark']]);

    const res = {
      getHeader: (name: string) => headers.get(name) as string | undefined,
      setHeader: (name: string, value: unknown) => headers.set(name, value),
    };

    const { auth } = await createAuthContext(options({ trustedHops: 1 })).node({
      req: {
        headers: { 'x-forwarded-for': ['203.0.113.9'], origin: [ORIGIN, 'x'] as never },
      },
      res,
    });

    expect(auth.meta).toEqual({ ip: '203.0.113.9', userAgent: '', origin: ORIGIN });
    expect((headers.get('set-cookie') as string[])[0]).toBe('theme=dark');
    expect(headers.get('set-cookie')).toHaveLength(3);
  });

  it('answers internal when resolving throws something that is not an Error', async () => {
    const env = options();
    const logged = vi.spyOn(env.auth.context.logger, 'error');

    vi.spyOn(env.auth, 'validateRequest').mockRejectedValue('down');

    await expect(
      createAuthContext(env).fetch({
        req: new Request(ORIGIN, { headers: { cookie: 'session=abc' } }),
        resHeaders: new Headers(),
      }),
    ).rejects.toThrow('internal');

    expect(logged).toHaveBeenCalledWith('auth-trpc could not resolve the request', {
      error: 'string',
    });
  });
});

describe('the auth state', () => {
  it('has no user when signed out, and loads the user once per request', async () => {
    const env = makeAuth();

    const signedOut = await createAuthContext(options({ auth: env.auth })).fetch({
      req: new Request(ORIGIN),
      resHeaders: new Headers(),
    });

    await expect(signedOut.auth.user()).resolves.toBeNull();

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: { ip: '::1' } });

    const login = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: { ip: '::1' } });

    if (!login.ok || login.value.kind !== 'session') throw new Error('no session');

    const find = vi.spyOn(env.stores.users, 'findById');

    const signedIn = await createAuthContext(options({ auth: env.auth })).fetch({
      req: new Request(ORIGIN, { headers: { cookie: `session=${login.value.session.token}` } }),
      resHeaders: new Headers(),
    });

    await signedIn.auth.user();
    await signedIn.auth.user();
    expect(find).toHaveBeenCalledTimes(1);
  });
});

describe('the cookie writers', () => {
  const issued = { cookie: {}, deviceCookie: {}, session: { id: 's' } } as never;

  it('refuse on ctx.auth itself, before writing anything or signing out', async () => {
    const env = makeAuth();
    const logout = vi.spyOn(env.auth, 'logout');
    const resHeaders = new Headers();

    const { auth } = await createAuthContext(options({ auth: env.auth })).fetch({
      req: new Request(ORIGIN, { method: 'POST' }),
      resHeaders,
    });

    // Not on the type: untyped code (or a cast) reaches the refusals.
    const untyped = auth as unknown as AuthWriter;

    expect(() => untyped.setSession(issued)).toThrow(AuthConfigError);
    expect(() => untyped.clearSession({} as never)).toThrow(/marked writesCookies/u);
    expect(() => untyped.signOut()).toThrow(AuthConfigError);
    expect(logout).not.toHaveBeenCalled();
    expect(resHeaders.getSetCookie()).toEqual([]);
  });

  it('come only through writesCookies, as a view that leaves ctx.auth unchanged', async () => {
    const middleware = new WritesCookiesMiddleware();
    const resHeaders = new Headers();
    const ctx = await trustedContext({}, resHeaders);
    let handed: { auth: AuthWriter } | undefined;

    await middleware.use({
      ctx,
      type: 'mutation',
      next: async (opts) => {
        handed = opts?.ctx as { auth: AuthWriter };

        return Promise.resolve('ran');
      },
    });

    expect(handed?.auth.meta).toBe(ctx.auth.meta);

    const cleared = handed?.auth.clearSession({
      name: 'session',
      value: '',
      attributes: { httpOnly: true, secure: false, sameSite: 'lax', path: '/', maxAge: 0 },
    });

    // The blank session cookie, a fresh pre-session and a CSRF cookie bound to it.
    const written = resHeaders.getSetCookie().map((line) => line.split('=')[0]);

    expect(written).toEqual(['session', 'presession', 'csrf']);
    expect(resHeaders.getSetCookie()[2]).toContain(`csrf=${cleared?.csrfToken ?? 'missing'}`);
    expect(() => (ctx.auth as unknown as AuthWriter).setSession(issued)).toThrow(AuthConfigError);

    // On a streamed batch the procedure never runs.
    const next = vi.fn(async () => Promise.resolve('ran'));

    await expect(
      middleware.use({
        ctx: await trustedContext({ 'trpc-accept': 'application/jsonl' }),
        type: 'mutation',
        next,
      }),
    ).rejects.toThrow(/httpBatchLink or httpLink/u);

    // Nor on a subscription, whose response is a stream as well.
    await expect(middleware.use({ ctx, type: 'subscription', next })).rejects.toThrow(
      /cannot mark a procedure of type subscription: its response is a stream/u,
    );

    // Nor on a query, which skips the CSRF check (A104), nor on any type tRPC
    // might add that is not a mutation.
    await expect(middleware.use({ ctx, type: 'query', next })).rejects.toThrow(
      /cannot mark a procedure of type query: a query skips the CSRF check/u,
    );

    await expect(middleware.use({ ctx, type: 'unknown', next })).rejects.toThrow(
      /cannot mark a procedure of type unknown: only a mutation passes the CSRF check/u,
    );

    expect(next).not.toHaveBeenCalled();
  });

  it('let one procedure per request write, and only once', async () => {
    const resHeaders = new Headers();
    const ctx = await trustedContext({}, resHeaders);

    const middleware = new WritesCookiesMiddleware();
    let writer: AuthWriter | undefined;

    await middleware.use({
      ctx,
      type: 'mutation',
      next: async (opts) => {
        writer = (opts?.ctx as { auth: AuthWriter }).auth;

        return Promise.resolve('ran');
      },
    });

    // A second marked procedure in the same request is refused before it runs.
    const next = vi.fn(async () => Promise.resolve('ran'));

    await expect(middleware.use({ ctx, type: 'mutation', next })).rejects.toThrow(
      /already has one/u,
    );

    expect(next).not.toHaveBeenCalled();

    // And the writers themselves write once: a second call throws before writing.
    const blank = {
      name: 'session',
      value: '',
      attributes: { httpOnly: true, secure: false, sameSite: 'lax', path: '/', maxAge: 0 },
    } as const;

    writer?.clearSession(blank);

    const written = resHeaders.getSetCookie().length;

    expect(() => writer?.clearSession(blank)).toThrow(/already wrote/u);
    expect(() => writer?.setSession(issued)).toThrow(AuthConfigError);
    await expect(writer?.signOut()).rejects.toThrow(AuthConfigError);
    expect(resHeaders.getSetCookie()).toHaveLength(written);
  });

  it('decides streaming exactly as tRPC does', () => {
    const cases: [Record<string, string>, boolean][] = [
      [{ 'trpc-accept': 'application/jsonl' }, true],
      [{ accept: 'application/jsonl' }, true],
      [{ accept: 'text/html, application/jsonl' }, true],
      [{ accept: 'text/html,  application/jsonl ,*/*' }, true],
      // trpc-accept wins whenever present, whatever its value.
      [{ 'trpc-accept': 'application/json', accept: 'application/jsonl' }, false],
      [{ 'trpc-accept': '', accept: 'application/jsonl' }, false],
      // Case-sensitive, as in tRPC.
      [{ 'trpc-accept': 'Application/JSONL' }, false],
      [{ accept: 'Application/JSONL' }, false],
      [{ accept: 'application/jsonl;q=0.9' }, false],
      [{ accept: 'application/json' }, false],
      [{}, false],
    ];

    for (const [headers, streamed] of cases) {
      expect(
        isStreamedRequest((name) => headers[name]),
        JSON.stringify(headers),
      ).toBe(streamed);
    }
  });
});

describe('authErrorFormatter', () => {
  const shape = (stack?: string) => ({
    message: 'That name is taken',
    code: -32009,
    data: { code: 'CONFLICT', httpStatus: 409, stack },
  });

  it('keeps an app error of its own and its message, never its stack', () => {
    const error = new TRPCError({ code: 'CONFLICT', message: 'That name is taken' });

    expect(authErrorFormatter({ shape: shape('/srv/app/dist/router.js:12:7'), error })).toEqual({
      message: 'That name is taken',
      code: -32009,
      data: { code: 'CONFLICT', httpStatus: 409, auth: null, input: null },
    });
  });

  it('gives the request errors tRPC raises a fixed message, never the parser text', () => {
    for (const [code, message] of [
      ['BAD_REQUEST', 'bad_request'],
      ['PARSE_ERROR', 'parse_error'],
      ['METHOD_NOT_SUPPORTED', 'method_not_supported'],
      ['UNSUPPORTED_MEDIA_TYPE', 'unsupported_media_type'],
      ['PAYLOAD_TOO_LARGE', 'payload_too_large'],
      ['NOT_FOUND', 'not_found'],
    ] as const) {
      const error = new TRPCError({ code, message: `Unexpected token 'S', "SECRETTOKE"...` });
      const formatted = authErrorFormatter({ shape: shape('trace'), error });

      expect(formatted.message).toBe(message);
      expect(JSON.stringify(formatted)).not.toContain('SECRET');
      expect(formatted.data).not.toHaveProperty('stack');
    }
  });
});

describe('the middleware bodies', () => {
  const t = initTRPC.context<{ auth: AuthState }>().create();
  const { csrf, role, rateLimited } = createAuthMiddlewares(t);

  async function contextFor(env: AuthContextOptions, method: string, headers: HeadersInit) {
    return createAuthContext(env).fetch({
      req: new Request(ORIGIN, { method, headers }),
      resHeaders: new Headers(),
    });
  }

  it('lets a query through csrf, and refuses a forged mutation', async () => {
    const router = t.router({
      read: t.procedure.use(csrf).query(() => 'read'),
      write: t.procedure.use(csrf).mutation(() => 'wrote'),
    });

    const caller = t.createCallerFactory(router)(
      await contextFor(options(), 'POST', { origin: 'https://evil.example' }),
    );

    await expect(caller.read()).resolves.toBe('read');
    await expect(caller.write()).rejects.toThrow('forbidden');
  });

  it('refuses a context it did not build, and a role check without the roles option', async () => {
    const router = t.router({
      write: t.procedure.use(csrf).mutation(() => 'wrote'),
      admin: t.procedure.use(role('admin')).query(() => 'admin'),
    });

    await expect(
      t
        .createCallerFactory(router)({ auth: null as never })
        .write(),
    ).rejects.toThrow(/createAuthContext/u);

    const env = makeAuth();

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: { ip: '::1' } });

    const login = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: { ip: '::1' } });

    if (!login.ok || login.value.kind !== 'session') throw new Error('no session');

    const ctx = await contextFor(options({ auth: env.auth }), 'GET', {
      cookie: `session=${login.value.session.token}`,
    });

    await expect(t.createCallerFactory(router)(ctx).admin()).rejects.toThrow(/roles` option/u);
  });

  it('refuses bad arguments when a middleware is made', () => {
    expect(() => role()).toThrow(/at least one role/u);
    expect(() => rateLimited('bad name')).toThrow(/Invalid rate limit name/u);
    expect(() => rateLimited('ok', { limit: 1, window: 'soon' as never })).toThrow();
  });

  it('refuses bad tiers, an unknown tier and a bad keyBy when the middlewares are made', () => {
    const tiers = (rateLimits: Record<string, unknown>) => () =>
      createAuthMiddlewares(t, { rateLimits: rateLimits as never });

    expect(tiers({ 'bad tier': { limit: 1, window: '1m' } })).toThrow(/Invalid rate limit tier/u);
    expect(tiers({ ok: { limit: 1, window: 'soon' } })).toThrow();
    expect(tiers({ ok: { limit: 1, window: '1m', keyBy: 'email' } })).toThrow(/keyBy must be/u);

    const made = createAuthMiddlewares(t, { rateLimits: { strict: { limit: 1, window: '1m' } } });

    expect(() => made.rateLimited('x', 'lax' as never)).toThrow(/Unknown rate limit tier: lax/u);
    expect(() => made.rateLimited('x', 'constructor' as never)).toThrow(/Unknown rate limit tier/u);

    expect(() => rateLimited('x', { limit: 1, window: '1m', keyBy: 'device' as never })).toThrow(
      /keyBy must be/u,
    );

    expect(() => RateLimitMiddleware('bad name')).toThrow(/Invalid rate limit name/u);
  });

  it('picks the named tier, then the tier named like the limit, then default, then 10 a minute', async () => {
    const env = options();
    const hit = vi.spyOn(env.auth.context.throttle, 'hit');

    const made = createAuthMiddlewares(t, {
      rateLimits: {
        default: { limit: 5, window: '1m' },
        search: { limit: 30, window: '1m' },
        strict: { limit: 2, window: '1h', keyBy: 'user' },
      },
    });

    const router = t.router({
      named: t.procedure.use(made.rateLimited('export', 'strict')).query(() => 1),
      byName: t.procedure.use(made.rateLimited('search')).query(() => 1),
      fallback: t.procedure.use(made.rateLimited('other')).query(() => 1),
      own: t.procedure.use(made.rateLimited('search', { limit: 7, window: '1m' })).query(() => 1),
      plain: t.procedure.use(rateLimited('plain')).query(() => 1),
    });

    const caller = t.createCallerFactory(router)(await contextFor(env, 'GET', {}));

    for (const call of [caller.named, caller.byName, caller.fallback, caller.own, caller.plain]) {
      await call();
    }

    // The counter store sees the window and limit only, never `keyBy`.
    expect(hit.mock.calls).toEqual([
      ['trpc:export:unknown', { limit: 2, window: '1h' }],
      ['trpc:search:unknown', { limit: 30, window: '1m' }],
      ['trpc:other:unknown', { limit: 5, window: '1m' }],
      ['trpc:search:unknown', { limit: 7, window: '1m' }],
      ['trpc:plain:unknown', { limit: 10, window: '1m' }],
    ]);
  });

  it('skips an exempt procedure in the nestjs-trpc class too, and counts the rest', async () => {
    const env = options();
    const ctx = await contextFor(env, 'GET', {});
    const next = () => Promise.resolve('ran');
    const Limited = RateLimitMiddleware('nest-exempt', { limit: 1, window: '1m', keyBy: 'user' });
    const exempt = { ctx, type: 'query', meta: { rateLimit: 'exempt' }, next };

    for (let i = 0; i < 3; i += 1) await expect(new Limited().use(exempt)).resolves.toBe('ran');

    await expect(new Limited().use({ ctx, type: 'query', next })).resolves.toBe('ran');
    await expect(new Limited().use({ ctx, type: 'query', next })).rejects.toThrow('rate_limited');
  });

  it('logs a non-Error from the counter store by its type', async () => {
    const env = options();
    const logged = vi.spyOn(env.auth.context.logger, 'error');

    vi.spyOn(env.auth.context.throttle, 'hit').mockRejectedValue('down');

    const router = t.router({ ping: t.procedure.use(rateLimited('ping')).query(() => 'pong') });
    const caller = t.createCallerFactory(router)(await contextFor(env, 'GET', {}));

    await expect(caller.ping()).rejects.toThrow('internal');

    expect(logged).toHaveBeenCalledWith('auth-trpc rate limit could not count the call', {
      limit: 'ping',
      error: 'string',
    });
  });

  it('runs the same bodies as nestjs-trpc classes', async () => {
    const ctx = await contextFor(options(), 'POST', {});
    const next = () => Promise.resolve('ran');

    await expect(new CsrfMiddleware().use({ ctx, type: 'query', next })).resolves.toBe('ran');

    await expect(new CsrfMiddleware().use({ ctx, type: 'mutation', next })).rejects.toThrow(
      'forbidden',
    );

    await expect(new AuthedMiddleware().use({ ctx, type: 'query', next })).rejects.toThrow(
      'session_expired',
    );
  });
});

describe('the schema walker', () => {
  it('walks a recursive schema once', () => {
    interface Node {
      token?: string | undefined;
      children: Node[];
    }

    const node: z.ZodType<Node> = z.lazy(() =>
      z.object({ token: z.string().optional(), children: z.array(node) }),
    );

    expect(secretKeys(node)).toEqual(['token']);
  });

  it('gives up on a child it cannot read', () => {
    const schema = { _zod: { def: { type: 'object', shape: { inner: { not: 'zod' } } } } };

    expect(secretKeys(schema)).toBeNull();
  });
});

describe('trusted proxies by address and the client IP header', () => {
  const nodeMeta = async (
    overrides: Partial<AuthContextOptions>,
    remoteAddress: string,
    headers: Record<string, string>,
  ) => {
    const res = { getHeader: () => undefined, setHeader: () => undefined };

    const { auth } = await createAuthContext(options(overrides)).node({
      req: { headers, socket: { remoteAddress } },
      res,
    });

    return auth.meta.ip;
  };

  it('refuses an unknown preset and X-Forwarded-For as the header at boot', () => {
    expect(() => createAuthContext(options({ trustedHops: ['localhost'] }))).toThrow(
      AuthConfigError,
    );

    expect(() =>
      createAuthContext(options({ trustedHops: ['loopback'], clientIpHeader: 'X-Forwarded-For' })),
    ).toThrow(AuthConfigError);

    // A hop count never checks the socket, so a direct client could set the header.
    expect(() =>
      createAuthContext(options({ trustedHops: 1, clientIpHeader: 'cf-connecting-ip' })),
    ).toThrow(/list of your edge/u);
  });

  it('reads the header on the Node adapters only through a trusted proxy', async () => {
    const trust = { trustedHops: ['uniquelocal'], clientIpHeader: 'CF-Connecting-IP' };

    expect(await nodeMeta(trust, '10.0.0.2', { 'cf-connecting-ip': '198.51.100.7' })).toBe(
      '198.51.100.7',
    );

    expect(await nodeMeta(trust, '203.0.113.50', { 'cf-connecting-ip': '198.51.100.7' })).toBe(
      '203.0.113.50',
    );

    expect(
      await nodeMeta(trust, '10.0.0.2', {
        'cf-connecting-ip': '198.51.100.7, 198.51.100.8',
        'x-forwarded-for': '203.0.113.9',
      }),
    ).toBe('203.0.113.9');
  });

  it('reads the header on the fetch adapter only from a trusted peer address', async () => {
    const context = createAuthContext(
      options({ trustedHops: ['loopback'], clientIpHeader: 'cf-connecting-ip' }),
    );

    const ip = async (remoteAddress: string) =>
      (
        await context.fetch(
          {
            req: new Request(ORIGIN, { headers: { 'cf-connecting-ip': '198.51.100.7' } }),
            resHeaders: new Headers(),
          },
          { remoteAddress },
        )
      ).auth.meta.ip;

    expect(await ip('127.0.0.1')).toBe('198.51.100.7');
    expect(await ip('203.0.113.50')).toBe('203.0.113.50');
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
    const resHeaders = new Headers();

    await createAuthContext(options({ auth })).fetch({
      req: new Request(ORIGIN, { headers: { cookie: `${auth.cookieName}=${token}` } }),
      resHeaders,
    });

    return resHeaders.getSetCookie().some((line) => line.startsWith(`${auth.cookieName}=;`));
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
