// Unit tests: the boot checks, the request adapters, the error formatter, the
// middleware bodies alone, and the schema walker's corners.
import { AuthConfigError, createAuth } from '@noctcore/auth';
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
  type AuthContextOptions,
  type AuthState,
  WritesCookiesMiddleware,
} from '../src';
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

describe('cookie writes on a streamed batch', () => {
  it('throws a configuration error from every writer, before the core signs out', async () => {
    const env = makeAuth();
    const logout = vi.spyOn(env.auth, 'logout');
    const resHeaders = new Headers();

    const { auth } = await createAuthContext(options({ auth: env.auth })).fetch({
      req: new Request(ORIGIN, {
        method: 'POST',
        headers: { 'trpc-accept': 'application/jsonl' },
      }),
      resHeaders,
    });

    const issued = { cookie: {}, deviceCookie: {}, session: { id: 's' } } as never;

    expect(() => auth.setSession(issued)).toThrow(AuthConfigError);
    expect(() => auth.clearSession({} as never)).toThrow(/httpBatchLink or httpLink/u);
    await expect(auth.signOut()).rejects.toThrow(AuthConfigError);
    expect(logout).not.toHaveBeenCalled();
    expect(resHeaders.getSetCookie()).toEqual([]);
  });

  it('refuses through the nestjs-trpc class too, and passes an ordinary request', async () => {
    const make = (headers: Record<string, string>) =>
      createAuthContext(options()).fetch({
        req: new Request(ORIGIN, { method: 'POST', headers }),
        resHeaders: new Headers(),
      });

    const next = vi.fn(async () => Promise.resolve('ran'));
    const middleware = new WritesCookiesMiddleware();

    await expect(
      middleware.use({
        ctx: await make({ 'trpc-accept': 'application/jsonl' }),
        type: 'mutation',
        next,
      }),
    ).rejects.toThrow(AuthConfigError);

    expect(next).not.toHaveBeenCalled();

    await expect(middleware.use({ ctx: await make({}), type: 'mutation', next })).resolves.toBe(
      'ran',
    );
  });
});

describe('authErrorFormatter', () => {
  const shape = (stack?: string) => ({
    message: 'No such post',
    code: -32004,
    data: { code: 'NOT_FOUND', httpStatus: 404, stack },
  });

  it('keeps an app error of its own and its message, never its stack', () => {
    const error = new TRPCError({ code: 'NOT_FOUND', message: 'No such post' });

    expect(authErrorFormatter({ shape: shape('/srv/app/dist/router.js:12:7'), error })).toEqual({
      message: 'No such post',
      code: -32004,
      data: { code: 'NOT_FOUND', httpStatus: 404, auth: null, input: null },
    });
  });

  it('gives the request errors tRPC raises a fixed message, never the parser text', () => {
    for (const [code, message] of [
      ['BAD_REQUEST', 'bad_request'],
      ['PARSE_ERROR', 'parse_error'],
      ['METHOD_NOT_SUPPORTED', 'method_not_supported'],
      ['UNSUPPORTED_MEDIA_TYPE', 'unsupported_media_type'],
      ['PAYLOAD_TOO_LARGE', 'payload_too_large'],
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
