import type { AppAuth } from '../node-server/auth.ts';
import {
  acceptedOutput,
  authErrorFormatter,
  createAuthMiddlewares,
  csrfTokenOutput,
  loginInput,
  loginOutput,
  reauthenticateInput,
  registerInput,
  requestPasswordResetInput,
  sessionListOutput,
  toTRPCError,
  userOutput,
  type AuthContextOf,
} from '@noctcore/auth-trpc';
import { initTRPC } from '@trpc/server';
import { z } from 'zod';

// ctx.auth from createAuthContext, typed by your createAuth result.
export type Context = AuthContextOf<AppAuth>;

// The formatter keeps internal messages, stacks and submitted values out of
// every error the client sees.
const t = initTRPC.context<Context>().create({ errorFormatter: authErrorFormatter });

// Build every procedure on these two: assertProceduresGuarded fails on one
// that uses neither.
const { publicProcedure, protectedProcedure, freshAuth, rateLimited } = createAuthMiddlewares(t);

export function createAppRouter(auth: AppAuth) {
  return t.router({
    // A query: hands the page its pre-session and CSRF cookies on first load.
    session: publicProcedure.query(async ({ ctx }) => ({ signedIn: (await ctx.auth.user()) !== null })),

    register: publicProcedure
      .input(registerInput)
      .output(acceptedOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.register({ ...input, meta: ctx.auth.meta });

        if (!result.ok) throw toTRPCError(result);

        // The same answer for a new address and a taken one.
        return { status: 'accepted' as const };
      }),

    login: publicProcedure
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

    requestPasswordReset: publicProcedure
      .input(requestPasswordResetInput)
      .output(acceptedOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.requestPasswordReset({ ...input, meta: ctx.auth.meta });

        if (!result.ok) throw toTRPCError(result);

        return { status: 'accepted' as const };
      }),

    logout: publicProcedure.output(csrfTokenOutput).mutation(({ ctx }) => ctx.auth.signOut()),

    // The output schema strips everything but id, email and emailVerified.
    me: protectedProcedure.output(userOutput).query(({ ctx }) => ctx.user),

    sessions: protectedProcedure
      .output(sessionListOutput)
      .query(({ ctx }) => auth.sessions.list(ctx.session)),

    // Re-entering the password rotates the session: setSession writes the new
    // cookie and a CSRF token bound to it.
    reauthenticate: protectedProcedure
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

    // Your own sensitive action: a password proof from the last 5 minutes.
    exportData: protectedProcedure
      .use(freshAuth('5m'))
      .use(rateLimited('export', { limit: 3, window: '1h' }))
      .output(z.object({ queued: z.boolean() }))
      .mutation(() => ({ queued: true })),
  });
}

export type AppRouter = ReturnType<typeof createAppRouter>;
