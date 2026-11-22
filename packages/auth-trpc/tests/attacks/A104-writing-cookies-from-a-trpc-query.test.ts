// A104: writing the session from a tRPC query a link on another site can run.
//
// The CSRF check runs on mutations only: a query must not change state. A
// procedure marked `writesCookies` gets `setSession`, `signOut` and
// `clearSession`, so if it is a query, nothing checks where the call came
// from. tRPC runs a query on a GET, and the session cookie is `SameSite=Lax`
// by default, so a top-level navigation from another site (a link, a
// redirect) carries it: the other site can sign the user out, or make any
// other session write the query does.
//
// Stopped by: auth-trpc src/middlewares.ts: `writesCookies`, and
//   `WritesCookiesMiddleware` on nestjs-trpc, refuse every call that is not a
//   mutation with an `AuthConfigError`, before the procedure runs and before
//   the writers are handed out; src/describe-procedures.ts:
//   `assertProceduresGuarded` names such a procedure in a test or at boot.
// Learn: CSRF (/auth/learn/csrf/); Build: Use with tRPC (/auth/build/trpc/)
import { AuthConfigError } from '@noctcore/auth';
import { initTRPC } from '@trpc/server';
import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  assertProceduresGuarded,
  createAuthContext,
  createAuthMiddlewares,
  describeProcedures,
  WritesCookiesMiddleware,
} from '../../src';
import { boot, Browser, CSRF_SECRET, EMAIL, ORIGIN, type Booted, type Context } from '../support';

/** The developer mistake: a sign-out as a query, marked to write cookies. */
function mistakenRouter() {
  const t = initTRPC.context<Context>().create();
  const { publicProcedure, writesCookies } = createAuthMiddlewares(t);

  const handler = vi.fn(async ({ ctx }: { ctx: { auth: { signOut(): Promise<unknown> } } }) => {
    await ctx.auth.signOut();

    return 'signed out';
  });

  return {
    handler,
    router: t.router({ signOutLink: publicProcedure.use(writesCookies).query(handler) }),
  };
}

describe('A104 writing cookies from a tRPC query', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('refuses a cross-site GET to a writesCookies query before the handler runs', async () => {
    booted = await boot();

    const browser = new Browser(booted);

    await browser.signIn();

    const session = browser.cookies.get('session');

    expect(session).toBeDefined();

    const { router, handler } = mistakenRouter();

    const authContext = createAuthContext({
      auth: booted.auth,
      trustedHops: 1,
      csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    });

    const errors: unknown[] = [];

    // What a top-level navigation from another site sends: a GET, no Origin,
    // `Sec-Fetch-Site: cross-site`, no CSRF header, and the Lax session cookie.
    const response = await fetchRequestHandler({
      endpoint: '/trpc',
      req: new Request(`${ORIGIN}/trpc/signOutLink`, {
        method: 'GET',
        headers: {
          'sec-fetch-site': 'cross-site',
          'x-forwarded-for': '198.51.100.7',
          cookie: `session=${session ?? ''}`,
        },
      }),
      router,
      createContext: (opts) => authContext.fetch(opts, { remoteAddress: '127.0.0.1' }),
      onError: ({ error }) => errors.push(error.cause),
    });

    expect(response.status).toBe(500);
    expect(handler).not.toHaveBeenCalled();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(AuthConfigError);
    expect((errors[0] as Error).message).toMatch(/cannot mark a query/u);

    // No session cookie was cleared, and the session is still valid.
    expect(response.headers.getSetCookie().some((line) => line.startsWith('session='))).toBe(false);
    await expect(browser.client.me.query()).resolves.toMatchObject({ email: EMAIL });
  });

  it('refuses a query on nestjs-trpc too, before the writers are handed out', async () => {
    booted = await boot();

    const authContext = createAuthContext({
      auth: booted.auth,
      trustedHops: 1,
      csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    });

    const ctx = await authContext.fetch({
      req: new Request(ORIGIN, { headers: { 'sec-fetch-site': 'cross-site' } }),
      resHeaders: new Headers(),
    });

    const next = vi.fn(async () => Promise.resolve('ran'));

    await expect(new WritesCookiesMiddleware().use({ ctx, type: 'query', next })).rejects.toThrow(
      /cannot mark a query: a query skips the CSRF check/u,
    );

    expect(next).not.toHaveBeenCalled();
  });

  it('names a marked query and a marked subscription in assertProceduresGuarded', () => {
    const { router } = mistakenRouter();

    expect(describeProcedures(router)).toEqual([
      {
        path: 'signOutLink',
        type: 'query',
        access: 'public',
        conflicting: false,
        writesCookies: true,
      },
    ]);

    expect(() => assertProceduresGuarded(router)).toThrow(
      /signOutLink: writesCookies on a query; write cookies from a mutation/u,
    );

    const t = initTRPC.context<Context>().create();
    const { publicProcedure, writesCookies } = createAuthMiddlewares(t);

    const mixed = t.router({
      signIn: publicProcedure.use(writesCookies).mutation(() => 'ok'),
      watch: publicProcedure.use(writesCookies).subscription(async function* () {
        yield await Promise.resolve('never');
      }),
    });

    expect(() => assertProceduresGuarded(mixed)).toThrow(
      /^(?![\s\S]*signIn)[\s\S]*watch: writesCookies on a subscription/u,
    );
  });
});
