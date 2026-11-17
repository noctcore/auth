// End to end on nestjs-trpc: a Nest app on Express with TRPCModule, the
// adapter's context and its middleware classes, called over HTTP the way the
// tRPC client calls it. The classes run the same bodies as plain tRPC, so this
// pins the wiring: the closed default, the public marker, CSRF on mutations,
// roles, and the refusal of a public procedure that asks for a role.
import 'reflect-metadata';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Ctx, Input, Mutation, Query, Router, TRPCModule, UseMiddlewares } from 'nestjs-trpc';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  AuthGuardMiddleware,
  authErrorFormatter,
  createAuthContext,
  FreshAuthMiddleware,
  loginInput,
  loginOutput,
  RateLimitMiddleware,
  RoleMiddleware,
  toTRPCError,
  userOutput,
  WritesCookiesMiddleware,
  type AuthState,
  type AuthWriter,
  type NodeContextInput,
  type Principal,
} from '../src';
import { Browser, CSRF_SECRET, EMAIL, makeAuth, ORIGIN, PASSWORD } from './support';

const AdminOnly = RoleMiddleware('admin');
const Fresh = FreshAuthMiddleware('1m');
const Limited = RateLimitMiddleware('nest-ping', { limit: 1, window: '1m' });

let current: ReturnType<typeof makeAuth>;
let authContext: ReturnType<typeof createAuthContext>;
const roles = new Map<string, readonly string[]>();

class AppContext {
  create(opts: unknown) {
    return authContext.node(opts as NodeContextInput);
  }
}

type Ctx = { auth: AuthState } & Partial<Principal>;
type WriterCtx = { auth: AuthWriter };

@Router({ alias: 'account' })
class AccountRouter {
  @Query({ output: z.object({ ok: z.boolean() }), meta: { auth: 'public' } })
  health() {
    return { ok: true };
  }

  @UseMiddlewares(WritesCookiesMiddleware)
  @Mutation({ input: loginInput, output: loginOutput, meta: { auth: 'public' } })
  async login(@Input() input: z.infer<typeof loginInput>, @Ctx() ctx: WriterCtx) {
    const result = await current.auth.login({ ...input, meta: ctx.auth.meta });

    if (!result.ok) throw toTRPCError(result);
    if (result.value.kind === 'challenge') return result.value;

    return { kind: 'session' as const, ...ctx.auth.setSession(result.value.session) };
  }

  /** Not marked writesCookies: the writer refuses before the core signs out. */
  @Mutation({ output: z.object({ csrfToken: z.string() }) })
  async logout(@Ctx() ctx: Ctx) {
    return (ctx as unknown as WriterCtx).auth.signOut();
  }

  /** Nobody marked it: the global guard must close it. */
  @Query({ output: userOutput })
  me(@Ctx() ctx: Ctx) {
    return { ...ctx.user, passwordHash: 'plain:hunter2' };
  }

  @Mutation({ output: z.object({ done: z.boolean() }) })
  write() {
    return { done: true };
  }

  @UseMiddlewares(AdminOnly)
  @Query({ output: z.object({ admin: z.boolean() }) })
  admin() {
    return { admin: true };
  }

  @UseMiddlewares(Fresh)
  @Mutation({ output: z.object({ done: z.boolean() }) })
  sensitive() {
    return { done: true };
  }

  @UseMiddlewares(Limited)
  @Query({ output: z.object({ pong: z.boolean() }), meta: { auth: 'public' } })
  ping() {
    return { pong: true };
  }

  /** Public and a role at once: refused on every call, never read one way. */
  @UseMiddlewares(AdminOnly)
  @Query({ output: z.object({ open: z.boolean() }), meta: { auth: 'public' } })
  confused() {
    return { open: true };
  }
}

interface Answer {
  readonly status: number;
  readonly body: {
    result?: { data: unknown };
    error?: { message: string; data: { code: string } };
  };
}

async function call(
  browser: Browser,
  url: string,
  path: string,
  input?: unknown,
  mutation = false,
) {
  const response = mutation
    ? await browser.fetch(`${url}/${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        ...(input === undefined ? {} : { body: JSON.stringify(input) }),
      })
    : await browser.fetch(`${url}/${path}`, { method: 'GET' });

  return { status: response.status, body: (await response.json()) as Answer['body'] };
}

describe('nestjs-trpc', () => {
  let app: INestApplication;

  afterEach(async () => {
    await app.close();
  });

  async function start() {
    current = makeAuth();
    roles.clear();

    authContext = createAuthContext({
      auth: current.auth,
      trustedHops: 1,
      csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
      roles: (user) => roles.get(user.id) ?? [],
    });

    const moduleRef = await Test.createTestingModule({
      imports: [
        TRPCModule.forRoot({
          basePath: '/trpc',
          context: AppContext,
          globalMiddlewares: [AuthGuardMiddleware],
          trpc: { errorFormatter: authErrorFormatter },
          logger: { log: () => undefined, error: () => undefined, warn: () => undefined },
        }),
      ],
      providers: [
        AccountRouter,
        AppContext,
        AuthGuardMiddleware,
        WritesCookiesMiddleware,
        AdminOnly,
        Fresh,
        Limited,
      ],
    }).compile();

    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0, '127.0.0.1');

    const registered = await current.auth.register({
      email: EMAIL,
      password: PASSWORD,
      meta: { ip: '203.0.113.1' },
    });

    if (!registered.ok) throw new Error('could not register the test user');

    const url = `http://127.0.0.1:${((app.getHttpServer() as Server).address() as AddressInfo).port}/trpc`;
    const browser = new Browser({ url, transport: fetch });

    return { url, browser };
  }

  it('closes a procedure nobody marked, and opens one marked public', async () => {
    const { url, browser } = await start();

    expect((await call(browser, url, 'account.health')).body.result?.data).toEqual({ ok: true });

    const me = await call(browser, url, 'account.me');

    expect(me.status).toBe(401);
    expect(me.body.error?.message).toBe('session_expired');

    // A valid CSRF token is not a session.
    const write = await call(browser, url, 'account.write', undefined, true);

    expect(write.status).toBe(401);
  });

  it('signs in with CSRF, strips unknown output keys and refuses a forged mutation', async () => {
    const { url, browser } = await start();

    await call(browser, url, 'account.health');

    const forged = new Browser({ url, transport: fetch });

    forged.override = { 'x-csrf-token': null };

    expect(
      (await call(forged, url, 'account.login', { email: EMAIL, password: PASSWORD }, true)).body
        .error?.message,
    ).toBe('forbidden');

    const login = await call(
      browser,
      url,
      'account.login',
      { email: EMAIL, password: PASSWORD },
      true,
    );

    expect(login.body.result?.data).toMatchObject({ kind: 'session' });

    const me = await call(browser, url, 'account.me');

    const user = await current.stores.users.findCredentialByEmail(EMAIL as never);

    expect(me.body.result?.data).toEqual({
      id: user?.id,
      email: EMAIL,
      emailVerified: false,
    });

    expect((await call(browser, url, 'account.write', undefined, true)).status).toBe(200);
    browser.override = { origin: 'https://evil.example' };
    expect((await call(browser, url, 'account.write', undefined, true)).status).toBe(403);
  });

  it('reads roles on every call, asks for a fresh proof and rate limits', async () => {
    const { url, browser } = await start();

    await call(browser, url, 'account.health');
    await call(browser, url, 'account.login', { email: EMAIL, password: PASSWORD }, true);

    expect((await call(browser, url, 'account.admin')).status).toBe(403);

    const user = await current.stores.users.findCredentialByEmail(EMAIL as never);

    roles.set(user?.id ?? '', ['admin']);
    expect((await call(browser, url, 'account.admin')).body.result?.data).toEqual({ admin: true });

    expect((await call(browser, url, 'account.sensitive', undefined, true)).status).toBe(200);
    current.clock.advance(2 * 60 * 1000);

    expect(
      (await call(browser, url, 'account.sensitive', undefined, true)).body.error?.message,
    ).toBe('fresh_auth_required');

    expect((await call(browser, url, 'account.ping')).status).toBe(200);
    expect((await call(browser, url, 'account.ping')).status).toBe(429);
  });

  it('refuses a cookie writer in a procedure not marked writesCookies, before the core runs', async () => {
    const { url, browser } = await start();

    await call(browser, url, 'account.health');

    const signedIn = await call(
      browser,
      url,
      'account.login',
      { email: EMAIL, password: PASSWORD },
      true,
    );

    // The marked procedure got the writers through the class.
    expect(signedIn.status).toBe(200);

    const logout = vi.spyOn(current.auth, 'logout');
    const answer = await call(browser, url, 'account.logout', undefined, true);

    expect(answer.status).toBe(500);
    expect(answer.body.error?.message).toBe('internal');
    expect(logout).not.toHaveBeenCalled();
    expect((await call(browser, url, 'account.me')).status).toBe(200);
  });

  it('refuses a procedure marked public that also asks for a role', async () => {
    const { url, browser } = await start();
    const answer = await call(browser, url, 'account.confused');

    expect(answer.status).toBe(500);
    expect(answer.body.error?.message).toBe('internal');
  });
});
