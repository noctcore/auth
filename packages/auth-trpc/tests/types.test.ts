// Type tests: what tRPC infers through the adapter's procedures and schemas.
// `bun run typecheck` checks them; the runtime part only keeps Vitest happy.
import type { AuthUser, ValidatedSession } from '@noctcore/auth';
import { initTRPC, type inferRouterInputs, type inferRouterOutputs } from '@trpc/server';
import { describe, expectTypeOf, it } from 'vitest';
import type { userOutput } from '../src';
import {
  authErrorFormatter,
  createAuthMiddlewares,
  loginInput,
  loginOutput,
  type AuthContextOf,
  type AuthState,
} from '../src';
import { makeAuth, type AppRouter } from './support';

interface AppUser extends AuthUser {
  readonly role: 'admin' | 'member';
}

describe('inferred types', () => {
  it('narrows the context to the app user and the session behind protectedProcedure', () => {
    const t = initTRPC
      .context<{ auth: AuthState<AppUser> }>()
      .create({ errorFormatter: authErrorFormatter });

    const { protectedProcedure, publicProcedure, role, freshAuth } = createAuthMiddlewares(t);

    const _router = t.router({
      me: protectedProcedure.query(({ ctx }) => {
        expectTypeOf(ctx.user).toEqualTypeOf<AppUser>();
        expectTypeOf(ctx.session).toEqualTypeOf<ValidatedSession<unknown>>();

        return ctx.user.role;
      }),
      admin: protectedProcedure
        .use(role('admin'))
        .use(freshAuth('5m'))
        .query(({ ctx }) => ctx.user.id),
      open: publicProcedure.query(async ({ ctx }) => {
        expectTypeOf(await ctx.auth.user()).toEqualTypeOf<AppUser | null>();

        return null;
      }),
      login: publicProcedure
        .input(loginInput)
        .output(loginOutput)
        .mutation(() => ({ kind: 'session' as const, csrfToken: 't' })),
    });

    type Inputs = inferRouterInputs<typeof _router>;
    type Outputs = inferRouterOutputs<typeof _router>;

    expectTypeOf<Outputs['me']>().toEqualTypeOf<'admin' | 'member'>();

    expectTypeOf<Inputs['login']>().toEqualTypeOf<{
      email: string;
      password: string;
      rememberMe?: boolean;
      captchaToken?: string;
    }>();

    expectTypeOf<Outputs['login']>().toEqualTypeOf<
      | { kind: 'session'; csrfToken: string }
      | { kind: 'challenge'; challenge: string; methods: readonly string[] }
    >();
  });

  it('derives the context from a createAuth result, session attributes included', () => {
    const { auth } = makeAuth();

    type Ctx = AuthContextOf<typeof auth>;

    expectTypeOf<NonNullable<Ctx['auth']['session']>['attributes']>().toEqualTypeOf<
      Record<string, never>
    >();

    const t = initTRPC.context<Ctx>().create();
    const { protectedProcedure } = createAuthMiddlewares(t);

    // ctx.session goes back into the flows without a cast.
    protectedProcedure.query(({ ctx }) => auth.sessions.list(ctx.session));
  });

  it('gives the cookie writers only to a procedure marked writesCookies', () => {
    type Auth = ReturnType<typeof makeAuth>['auth'];

    const t = initTRPC.context<AuthContextOf<Auth>>().create();
    const { publicProcedure, protectedProcedure, writesCookies } = createAuthMiddlewares(t);

    for (const procedure of [publicProcedure, protectedProcedure]) {
      procedure.mutation(({ ctx }) => {
        expectTypeOf(ctx.auth).not.toHaveProperty('setSession');
        expectTypeOf(ctx.auth).not.toHaveProperty('signOut');
        expectTypeOf(ctx.auth).not.toHaveProperty('clearSession');
      });
    }

    protectedProcedure.use(writesCookies).mutation(({ ctx }) => {
      expectTypeOf(ctx.auth).toHaveProperty('setSession');
      expectTypeOf(ctx.auth).toHaveProperty('signOut');
      expectTypeOf(ctx.auth).toHaveProperty('clearSession');

      // The session attributes and the principal survive the marker.
      expectTypeOf(ctx.auth.session).toEqualTypeOf<ValidatedSession<
        Record<string, never>
      > | null>();

      expectTypeOf(ctx.user.email).toBeString();
    });
  });

  it('types the outputs of the documented router by their schemas', () => {
    type Outputs = inferRouterOutputs<AppRouter>;

    expectTypeOf<Outputs['me']>().toEqualTypeOf<{
      id: string;
      email: string;
      emailVerified: boolean;
    }>();

    expectTypeOf<Outputs['leaky']>().toEqualTypeOf<ReturnType<typeof userOutput.parse>>();
  });

  it('types the tier names a procedure may pick', () => {
    const t = initTRPC.context<{ auth: AuthState }>().create();
    const plain = createAuthMiddlewares(t);

    const tiered = createAuthMiddlewares(t, {
      rateLimits: { strict: { limit: 2, window: '1h', keyBy: 'user' } },
    });

    expectTypeOf(tiered.rateLimited).toBeCallableWith('export', 'strict');
    expectTypeOf(tiered.rateLimited).toBeCallableWith('export', { limit: 1, window: '1m' });

    // @ts-expect-error: no tier of that name
    tiered.rateLimited.bind(null, 'export', 'lax');
    // @ts-expect-error: no tiers at all
    plain.rateLimited.bind(null, 'export', 'strict');
    // @ts-expect-error: keyBy is ip or user
    plain.rateLimited.bind(null, 'export', { limit: 1, window: '1m', keyBy: 'email' });
  });
});
