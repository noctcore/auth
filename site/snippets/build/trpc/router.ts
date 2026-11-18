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
  revokedOutput,
  revokeSessionInput,
  sessionListOutput,
  toTRPCError,
  userOutput,
  verifyEmailLinkInput,
  type AuthContextOf,
} from '@noctcore/auth-trpc';
import { initTRPC } from '@trpc/server';
import { z } from 'zod';

// ctx.auth from createAuthContext, typed by your createAuth result.
export type Context = AuthContextOf<AppAuth>;

// The formatter keeps stacks, submitted values and internal messages out of
// the errors tRPC and the adapter raise. Messages you throw yourself go out
// as you wrote them.
const t = initTRPC.context<Context>().create({ errorFormatter: authErrorFormatter });

// Build every procedure on these two: assertProceduresGuarded fails on one
// that uses neither.
const { publicProcedure, protectedProcedure, freshAuth, rateLimited, writesCookies } =
  createAuthMiddlewares(t);

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

    // writesCookies hands the procedure ctx.auth.setSession and signOut;
    // without it they are not there. On a streamed batch it refuses first.
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

    requestPasswordReset: publicProcedure
      .input(requestPasswordResetInput)
      .output(acceptedOutput)
      .mutation(async ({ ctx, input }) => {
        const result = await auth.requestPasswordReset({ ...input, meta: ctx.auth.meta });

        if (!result.ok) throw toTRPCError(result);

        return { status: 'accepted' as const };
      }),

    // A mutation (a POST), called when the user clicks Confirm on the page the
    // mail links to, with the token from its URL fragment; never on page load,
    // so a mail scanner that fetches the link verifies nothing. ctx.auth.session
    // is resolved on public procedures too: a link for another account is refused.
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

        // Signed in as this account: the session was re-issued. Otherwise
        // nobody is signed in (with linkWithoutSession) and the page says so.
        const issued = result.value.session;

        return issued ? { verified: true, ...ctx.auth.setSession(issued) } : { verified: true };
      }),

    logout: publicProcedure
      .use(writesCookies)
      .output(csrfTokenOutput)
      .mutation(({ ctx }) => ctx.auth.signOut()),

    // The output schema strips everything but id, email and emailVerified.
    me: protectedProcedure.output(userOutput).query(({ ctx }) => ctx.user),

    // Each session is named by its public handle, never its store key.
    sessions: protectedProcedure
      .output(sessionListOutput)
      .query(({ ctx }) => auth.sessions.list(ctx.session)),

    // Signs out one device by the handle the list showed. Another device needs
    // a fresh password proof; a handle that names none of the caller's
    // sessions answers { revoked: false }. Revoking the current one? Use logout.
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

    // Re-entering the password rotates the session: setSession writes the new
    // cookie and a CSRF token bound to it.
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

    // Your own sensitive action: a password proof from the last 5 minutes.
    exportData: protectedProcedure
      .use(freshAuth('5m'))
      .use(rateLimited('export', { limit: 3, window: '1h' }))
      .output(z.object({ queued: z.boolean() }))
      .mutation(() => ({ queued: true })),
  });
}

export type AppRouter = ReturnType<typeof createAppRouter>;
