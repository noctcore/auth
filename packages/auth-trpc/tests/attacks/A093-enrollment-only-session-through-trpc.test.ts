// A093: using an enrollment-only session for more than enrollment, on tRPC.
//
// Under the two-factor plugin's `enforcement`, a user who must set up a
// factor and is past the grace window still signs in, so the session can
// reach enrollment. If the adapter's session check does not read the
// session's standing, that session calls every protected procedure, and the
// requirement means nothing.
//
// Stopped by: auth-trpc src/middlewares.ts (`authed`, and every check built
//   on it, `role`, `freshAuth` and the nestjs-trpc `AuthGuardMiddleware`,
//   refuses an `enrollment-only` session with
//   `two_factor_enrollment_required` unless the procedure's meta says
//   `twoFactorEnrollment: true`; the marker opens nothing else).
// Learn: Build, "Two-factor" (/auth/build/two-factor/)
import type { SessionStanding } from '@noctcore/auth';
import { initTRPC } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import {
  AuthGuardMiddleware,
  AUTH_ERROR_TRPC_CODES,
  createAuthContext,
  createAuthMiddlewares,
  type AuthProcedureMeta,
  type AuthState,
} from '../../src';
import { CSRF_SECRET, EMAIL, makeAuth, ORIGIN, PASSWORD } from '../support';

const MINUTE = 60 * 1000;

const t = initTRPC.context<{ auth: AuthState }>().meta<AuthProcedureMeta>().create();
const { protectedProcedure, freshAuth, role } = createAuthMiddlewares(t);

const router = t.router({
  me: protectedProcedure.query(({ ctx }) => ctx.user.id),
  status: protectedProcedure
    .meta({ twoFactorEnrollment: true })
    .query(({ ctx }) => ctx.session.twoFactor ?? null),
  enroll: protectedProcedure
    .meta({ twoFactorEnrollment: true })
    .use(freshAuth())
    .query(() => 'enrolling'),
  admin: protectedProcedure
    .meta({ twoFactorEnrollment: true })
    .use(role('admin'))
    .query(() => 'admin'),
});

/** A signed-in caller whose session's standing is whatever `standing.current` is. */
async function signedIn(standing: { current: SessionStanding | undefined }) {
  const env = makeAuth({ secure: false }, undefined, undefined, {
    sessionStanding: () => standing.current,
  });

  await env.auth.register({ email: EMAIL, password: PASSWORD, meta: { ip: '::1' } });

  const login = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: { ip: '::1' } });

  if (!login.ok || login.value.kind !== 'session') throw new Error('no session');

  const context = createAuthContext({
    auth: env.auth,
    trustedHops: 0,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    roles: () => [],
  });

  const ctx = async () =>
    context.fetch({
      req: new Request(ORIGIN, {
        method: 'POST',
        headers: {
          origin: ORIGIN,
          'sec-fetch-site': 'same-origin',
          cookie: `session=${login.value.kind === 'session' ? login.value.session.token : ''}`,
        },
      }),
      resHeaders: new Headers(),
    });

  return { env, ctx, caller: async () => t.createCallerFactory(router)(await ctx()) };
}

const ENROLLMENT_ONLY: SessionStanding = { twoFactor: { state: 'enrollment-only' } };

describe('A093: an enrollment-only session through tRPC', () => {
  it('refuses every procedure not marked for enrollment, as FORBIDDEN', async () => {
    const { caller } = await signedIn({ current: ENROLLMENT_ONLY });

    await expect((await caller()).me()).rejects.toMatchObject({
      code: 'FORBIDDEN',
      message: 'two_factor_enrollment_required',
    });

    expect(AUTH_ERROR_TRPC_CODES.two_factor_enrollment_required).toBe('FORBIDDEN');
  });

  it('lets it call the marked procedures, which keep their own requirements', async () => {
    const { env, caller } = await signedIn({ current: ENROLLMENT_ONLY });

    await expect((await caller()).status()).resolves.toEqual({ state: 'enrollment-only' });
    await expect((await caller()).enroll()).resolves.toBe('enrolling');
    await expect((await caller()).admin()).rejects.toThrow('forbidden');

    env.clock.advance(11 * MINUTE);

    await expect((await caller()).enroll()).rejects.toThrow('fresh_auth_required');
  });

  it('reads the standing on every request, so a change applies without a new sign-in', async () => {
    const standing: { current: SessionStanding | undefined } = {
      current: { twoFactor: { state: 'grace', graceEndsAt: Date.now() + MINUTE } },
    };

    const { caller } = await signedIn(standing);

    await expect((await caller()).me()).resolves.toBeTypeOf('string');

    standing.current = ENROLLMENT_ONLY;
    await expect((await caller()).me()).rejects.toThrow('two_factor_enrollment_required');

    standing.current = undefined;
    await expect((await caller()).me()).resolves.toBeTypeOf('string');
  });

  it('holds on nestjs-trpc through the global guard', async () => {
    const { ctx } = await signedIn({ current: ENROLLMENT_ONLY });
    const next = () => Promise.resolve('ran');
    const guard = new AuthGuardMiddleware();

    await expect(guard.use({ ctx: await ctx(), type: 'query', next })).rejects.toThrow(
      'two_factor_enrollment_required',
    );

    await expect(
      guard.use({ ctx: await ctx(), type: 'query', meta: { twoFactorEnrollment: true }, next }),
    ).resolves.toBe('ran');
  });
});
