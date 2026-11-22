// A033: cross-site request forgery against a tRPC mutation.
//
// A page on another site posts to the tRPC endpoint with the user's cookies:
// with no Origin, its own Origin, a cross-site Sec-Fetch-Site, or a CSRF token
// it obtained for another browser or session. tRPC itself checks none of it,
// and a router that builds a procedure on `authed` without the `csrf` step in
// front of it would let the mutation through.
//
// Stopped by: auth-trpc src/context.ts (the three core checks, computed when
//   the context is built) and src/middlewares.ts: `csrf`, `publicProcedure`
//   and every session check refuse a mutation that failed them, so leaving
//   the `csrf` step out of a chain does not skip it; `writesCookies` (and
//   `WritesCookiesMiddleware` on nestjs-trpc) runs the check itself too, so
//   a cookie writer built on a bare `t.procedure` is never reachable forged.
// Learn: CSRF (/auth/learn/csrf/); core attacks A008, A021
import { initTRPC } from '@trpc/server';
import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createAuthContext,
  createAuthMiddlewares,
  WritesCookiesMiddleware,
  type AuthState,
} from '../../src';
import {
  boot,
  Browser,
  CSRF_SECRET,
  EMAIL,
  failure,
  ORIGIN,
  PASSWORD,
  type Booted,
  type Context,
} from '../support';

describe('A033 CSRF through tRPC', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('refuses a token minted for another browser, no Origin and the null Origin', async () => {
    booted = await boot();

    const victim = new Browser(booted);
    const attacker = new Browser(booted, '198.51.100.66');

    await victim.signIn();
    await attacker.signIn();

    for (const override of [
      // The attacker's own valid token, sent with the victim's cookies.
      { 'x-csrf-token': attacker.csrf },
      { origin: null },
      // The Origin that sandboxed frames send.
      { origin: 'null' },
    ]) {
      victim.override = override;
      expect((await failure(victim.client.echo.mutate({ note: 'x' }))).message).toBe('forbidden');
    }
  });

  it('refuses a forged mutation behind authed, freshAuth or role without the csrf step', async () => {
    booted = await boot();

    const { auth } = booted;
    const t = initTRPC.context<{ auth: AuthState }>().create();
    const { authed, freshAuth, role } = createAuthMiddlewares(t);

    const router = t.router({
      a: t.procedure.use(authed).mutation(() => 'ran'),
      b: t.procedure.use(freshAuth()).mutation(() => 'ran'),
      c: t.procedure.use(role('admin')).mutation(() => 'ran'),
    });

    const context = createAuthContext({
      auth,
      trustedHops: 0,
      csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
      roles: () => ['admin'],
    });

    const signedIn = await auth.login({ email: EMAIL, password: PASSWORD, meta: { ip: '::1' } });

    if (!signedIn.ok || signedIn.value.kind !== 'session') throw new Error('no session');

    const headers = new Headers({
      cookie: `session=${signedIn.value.session.token}`,
      origin: 'https://evil.example',
    });

    const ctx = await context.fetch({
      req: new Request(`${ORIGIN}/trpc/a`, { method: 'POST', headers }),
      resHeaders: new Headers(),
    });

    const caller = t.createCallerFactory(router)(ctx);

    await expect(caller.a()).rejects.toThrow('forbidden');
    await expect(caller.b()).rejects.toThrow('forbidden');
    await expect(caller.c()).rejects.toThrow('forbidden');
  });

  it('refuses a forged mutation marked writesCookies on a bare t.procedure', async () => {
    booted = await boot();

    const browser = new Browser(booted);

    await browser.signIn();

    const t = initTRPC.context<Context>().create();
    const { writesCookies } = createAuthMiddlewares(t);

    const handler = vi.fn(async ({ ctx }: { ctx: { auth: { signOut(): Promise<unknown> } } }) => {
      await ctx.auth.signOut();

      return 'signed out';
    });

    const router = t.router({ signOut: t.procedure.use(writesCookies).mutation(handler) });

    const authContext = createAuthContext({
      auth: booted.auth,
      trustedHops: 1,
      csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    });

    const call = async (headers: Record<string, string>) =>
      fetchRequestHandler({
        endpoint: '/trpc',
        req: new Request(`${ORIGIN}/trpc/signOut`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-forwarded-for': '198.51.100.7',
            ...headers,
          },
        }),
        router,
        createContext: (opts) => authContext.fetch(opts, { remoteAddress: '127.0.0.1' }),
      });

    const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');

    // Another site's form: its own Origin, cross-site, no token, the victim's cookies.
    const forged = await call({
      origin: 'https://evil.example',
      'sec-fetch-site': 'cross-site',
      cookie,
    });

    expect(forged.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
    await expect(browser.client.me.query()).resolves.toMatchObject({ email: EMAIL });

    // The nestjs-trpc class alone refuses the same forged request.
    const forgedCtx = await authContext.fetch({
      req: new Request(ORIGIN, {
        method: 'POST',
        headers: { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site', cookie },
      }),
      resHeaders: new Headers(),
    });

    const next = vi.fn(async () => Promise.resolve('ran'));

    await expect(
      new WritesCookiesMiddleware().use({ ctx: forgedCtx, type: 'mutation', next }),
    ).rejects.toThrow('forbidden');

    expect(next).not.toHaveBeenCalled();

    // The page itself still signs out, and the cookie is cleared.
    const legit = await call({
      origin: ORIGIN,
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': browser.csrf,
      cookie,
    });

    expect(legit.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);

    expect(legit.headers.getSetCookie().some((line) => /^session=;.*Max-Age=0/iu.test(line))).toBe(
      true,
    );
  });
});
