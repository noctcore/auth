// A real tRPC router wired the way the docs say, over the core's in-memory
// stores, served by the fetch adapter (in-process) or the standalone Node
// adapter (on a real port), and called with a real tRPC client through a
// browser-like fetch that keeps cookies and sends Origin, Sec-Fetch-Site and
// the CSRF header like a page would.
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  createAuth,
  type AuthConfig,
  type AuthUser,
  type SessionCookieConfig,
} from '@noctcore/auth';
import { manualClock, memoryStores, plainHasher, recordingMailer } from '@noctcore/auth/testing';
import {
  createTRPCClient,
  httpBatchLink,
  httpBatchStreamLink,
  httpLink,
  TRPCClientError,
} from '@trpc/client';
import { initTRPC } from '@trpc/server';
import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import { createHTTPHandler } from '@trpc/server/adapters/standalone';
import { z } from 'zod';
import {
  acceptedOutput,
  authErrorFormatter,
  createAuthContext,
  createAuthMiddlewares,
  csrfTokenOutput,
  loginInput,
  loginOutput,
  reauthenticateInput,
  registerInput,
  requestPasswordResetInput,
  revokedOutput,
  revokeSessionInput,
  sessionListOutput,
  toTRPCError,
  userOutput,
  verifyEmailLinkInput,
  type AuthContextOf,
  type AuthContextOptions,
} from '../src';

export const ORIGIN = 'http://app.test';
export const EMAIL = 'ada@example.com';
export const PASSWORD = 'correct horse battery staple';
export const CSRF_SECRET = 'csrf-secret-that-is-at-least-32-bytes-long';

type Verification = AuthConfig<AuthUser, Record<string, never>, []>['emailVerification'];
type Hooks = AuthConfig<AuthUser, Record<string, never>, []>['hooks'];

/**
 * `cookie` replaces the session cookie config (plain HTTP, `Lax`, by default);
 * `emailVerification` replaces the core's verification settings (codes by default);
 * `maxPerUser` replaces the per-user session cap (10 by default);
 * `hooks` adds app hooks (none by default).
 */
export function makeAuth(
  cookie: SessionCookieConfig = { secure: false },
  emailVerification?: Verification,
  maxPerUser?: number,
  hooks?: Hooks,
) {
  const clock = manualClock();
  const stores = memoryStores(clock);
  const mailer = recordingMailer();

  const auth = createAuth({
    stores,
    clock,
    password: { hasher: plainHasher(), breachCheck: false },
    session: { cookie, ...(maxPerUser === undefined ? {} : { maxPerUser }) },
    secret: 'auth-secret-that-is-at-least-32-bytes-long',
    urls: {
      resetPassword: (token) => `${ORIGIN}/reset#${token}`,
      verifyEmail: (token) => `${ORIGIN}/verify#${token}`,
    },
    ...(emailVerification ? { emailVerification } : {}),
    ...(hooks ? { hooks } : {}),
    mailer,
  });

  return { auth, clock, stores, mailer };
}

export type TestAuth = ReturnType<typeof makeAuth>['auth'];
export type Context = AuthContextOf<TestAuth>;

export function buildRouter(auth: TestAuth) {
  const t = initTRPC.context<Context>().create({ errorFormatter: authErrorFormatter });

  const { publicProcedure, protectedProcedure, freshAuth, role, rateLimited, writesCookies } =
    createAuthMiddlewares(t);

  return t.router({
    health: publicProcedure.query(() => ({ ok: true })),
    whoami: publicProcedure.query(async ({ ctx }) => ({
      user: (await ctx.auth.user())?.id ?? null,
    })),
    login: publicProcedure
      .use(writesCookies)
      .input(loginInput)
      .output(loginOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.login({
          ...input,
          deviceToken: ctx.auth.deviceToken,
          meta: ctx.auth.meta,
        });

        if (!result.ok) throw toTRPCError(result);
        if (result.value.kind === 'challenge') return result.value;

        return { kind: 'session' as const, ...ctx.auth.setSession(result.value.session) };
      }),
    register: publicProcedure
      .input(registerInput)
      .output(acceptedOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.register({ ...input, meta: ctx.auth.meta });

        if (!result.ok) throw toTRPCError(result);

        return { status: 'accepted' as const };
      }),
    requestReset: publicProcedure
      .input(requestPasswordResetInput)
      .output(acceptedOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.requestPasswordReset({ ...input, meta: ctx.auth.meta });

        if (!result.ok) throw toTRPCError(result);

        return { status: 'accepted' as const };
      }),
    // A mutation, so a mail scanner's GET never reaches it; the session, if
    // the request carries one, is passed so another account's is refused.
    verifyEmailLink: publicProcedure
      .use(writesCookies)
      .input(verifyEmailLinkInput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.verifyEmailLink({
          token: input.token,
          session: ctx.auth.session,
          meta: ctx.auth.meta,
        });

        if (!result.ok) throw toTRPCError(result);

        const issued = result.value.session;

        return {
          verified: true,
          signedIn: issued !== null,
          ...(issued && ctx.auth.setSession(issued)),
        };
      }),
    me: protectedProcedure.output(userOutput).query(({ ctx }) => ctx.user),
    /** Returns more than the user: the output schema must strip it. */
    leaky: protectedProcedure
      .output(userOutput)
      .query(({ ctx }) => ({ ...ctx.user, passwordHash: 'plain:hunter2', tokenHash: 'abc' })),
    meta: protectedProcedure.query(({ ctx }) => ctx.auth.meta),
    sessions: protectedProcedure
      .output(sessionListOutput)
      .query(({ ctx }) => auth.sessions.list(ctx.session)),
    /** Returns each session's store key too: the output schema must strip it. */
    leakySessions: protectedProcedure
      .output(sessionListOutput)
      .query(async ({ ctx }) =>
        (await auth.sessions.list(ctx.session)).map((s) => ({ ...s, id: ctx.session.id })),
      ),
    revokeSession: protectedProcedure
      .input(revokeSessionInput)
      .output(revokedOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.sessions.revoke({
          session: ctx.session,
          handle: input.handle,
          meta: ctx.auth.meta,
        });

        if (!result.ok) throw toTRPCError(result);

        return result.value;
      }),
    reauthenticate: protectedProcedure
      .use(writesCookies)
      .input(reauthenticateInput)
      .output(csrfTokenOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.reauthenticate({
          session: ctx.session,
          password: input.password,
          meta: ctx.auth.meta,
        });

        if (!result.ok) throw toTRPCError(result);

        return ctx.auth.setSession(result.value);
      }),
    sensitive: protectedProcedure.use(freshAuth()).mutation(() => ({ done: true })),
    verySensitive: protectedProcedure.use(freshAuth('1m')).mutation(() => ({ done: true })),
    admin: protectedProcedure.use(role('admin')).query(() => ({ admin: true })),
    limited: publicProcedure
      .use(rateLimited('ping', { limit: 2, window: '1m' }))
      .query(() => ({ pong: true })),
    echo: protectedProcedure
      .input(z.object({ note: z.string().max(5) }))
      .mutation(({ input }) => input),
    logout: publicProcedure
      .use(writesCookies)
      .output(csrfTokenOutput)
      .mutation(({ ctx }) => ctx.auth.signOut()),
    revokeAll: protectedProcedure
      .use(writesCookies)
      .output(csrfTokenOutput)
      .mutation(async ({ ctx }) => {
        const { cookie } = await auth.sessions.revokeAll({
          session: ctx.session,
          meta: ctx.auth.meta,
        });

        return ctx.auth.clearSession(cookie);
      }),
    boom: publicProcedure.query(() => {
      throw new Error('store failed for session key 4f2a');
    }),
  });
}

export type AppRouter = ReturnType<typeof buildRouter>;

export interface BootOptions {
  readonly roles?: Map<string, readonly string[]>;
  readonly options?: Partial<AuthContextOptions<AuthUser, Record<string, never>>>;
  readonly transport?: 'fetch' | 'node';
  /** The session cookie config, in place of plain HTTP with `Lax`. */
  readonly cookie?: SessionCookieConfig;
  /** The core's verification settings, in place of codes. */
  readonly emailVerification?: Verification;
  /** The per-user session cap, in place of 10. */
  readonly maxPerUser?: number;
  /** App hooks for the core (a `sessionStanding` hook, say). */
  readonly hooks?: Hooks;
}

export async function boot(overrides: BootOptions = {}) {
  const env = makeAuth(
    overrides.cookie,
    overrides.emailVerification,
    overrides.maxPerUser,
    overrides.hooks,
  );

  const roles = overrides.roles ?? new Map<string, readonly string[]>();

  const authContext = createAuthContext({
    auth: env.auth,
    trustedHops: 1,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    roles: (user) => roles.get(user.id) ?? [],
    ...overrides.options,
  });

  const router = buildRouter(env.auth);
  let server: Server | undefined;
  let url = `${ORIGIN}/trpc`;
  let transport: typeof fetch = fetch;

  if ((overrides.transport ?? 'fetch') === 'fetch') {
    transport = (input, init) =>
      fetchRequestHandler({
        endpoint: '/trpc',
        req: new Request(input as string, init),
        router,
        createContext: (opts) => authContext.fetch(opts, { remoteAddress: '127.0.0.1' }),
      });
  } else {
    const handler = createHTTPHandler({
      router,
      basePath: '/trpc/',
      createContext: (opts) => authContext.node(opts),
    });

    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((resolve) => server?.listen(0, '127.0.0.1', resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/trpc`;
  }

  const registered = await env.auth.register({
    email: EMAIL,
    password: PASSWORD,
    meta: { ip: '203.0.113.1' },
  });

  if (!registered.ok) throw new Error('could not register the test user');

  const user = await env.stores.users.findCredentialByEmail(EMAIL as never);

  const close = () =>
    new Promise<void>((resolve) => {
      if (server) server.close(() => resolve());
      else resolve();
    });

  return { ...env, router, roles, url, transport, close, userId: user?.id ?? '' };
}

export type Booted = Awaited<ReturnType<typeof boot>>;

/** Keeps cookies, and sends what a same-origin page sends, unless told otherwise. */
export class Browser {
  readonly cookies = new Map<string, string>();
  override: Record<string, string | null> = {};
  readonly client;
  lastSetCookies: string[] = [];
  lastStatus = 0;

  constructor(
    private readonly env: { readonly url: string; readonly transport: typeof fetch },
    private readonly ip = '198.51.100.7',
    link: 'plain' | 'stream' | 'batch' = 'plain',
  ) {
    const options = {
      url: env.url,
      fetch: (input: unknown, init: unknown) => this.fetch(input, init as RequestInit),
    };

    this.client = createTRPCClient<AppRouter>({
      links: [
        link === 'stream'
          ? httpBatchStreamLink(options)
          : link === 'batch'
            ? httpBatchLink(options)
            : httpLink(options),
      ],
    });
  }

  get csrf(): string {
    return this.cookies.get('csrf') ?? this.cookies.get('__Host-csrf') ?? '';
  }

  async fetch(input: unknown, init?: RequestInit): Promise<Response> {
    const headers: Record<string, string> = {
      ...(init?.headers as Record<string, string> | undefined),
      origin: ORIGIN,
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': this.csrf,
      'x-forwarded-for': this.ip,
      cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '),
    };

    for (const [key, value] of Object.entries(this.override)) {
      if (value === null) Reflect.deleteProperty(headers, key);
      else headers[key] = value;
    }

    const response = await this.env.transport(String(input), { ...init, headers });

    this.lastStatus = response.status;
    this.lastSetCookies = response.headers.getSetCookie();

    for (const line of this.lastSetCookies) {
      const [pair = '', ...attributes] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq);
      const value = decodeURIComponent(pair.slice(eq + 1));

      if (attributes.some((a) => a.trim().toLowerCase() === 'max-age=0')) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }

    return response;
  }

  /** Visits a page (which hands out the CSRF cookie) and signs in. */
  async signIn(email = EMAIL, password = PASSWORD) {
    await this.client.health.query();

    return this.client.login.mutate({ email, password });
  }
}

/** The error a call failed with, as the client saw it. */
export async function failure(call: Promise<unknown>): Promise<TRPCClientError<AppRouter>> {
  try {
    await call;
  } catch (error) {
    if (error instanceof TRPCClientError) return error as TRPCClientError<AppRouter>;

    throw error;
  }

  throw new Error('expected the call to fail');
}
