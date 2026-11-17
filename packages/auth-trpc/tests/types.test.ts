// Type tests: what tRPC infers through the adapter's procedures and schemas.
// `bun run typecheck` checks them; the runtime part only keeps Vitest happy.
import type { AuthUser, StoredSession } from '@noctcore/auth';
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
        expectTypeOf(ctx.session).toEqualTypeOf<StoredSession<unknown>>();

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

  it('types the outputs of the documented router by their schemas', () => {
    type Outputs = inferRouterOutputs<AppRouter>;

    expectTypeOf<Outputs['me']>().toEqualTypeOf<{
      id: string;
      email: string;
      emailVerified: boolean;
    }>();

    expectTypeOf<Outputs['leaky']>().toEqualTypeOf<ReturnType<typeof userOutput.parse>>();
  });
});
