// A034: a procedure left open because nobody marked it.
//
// tRPC has no global guard. A procedure built on `t.procedure` instead of the
// guarded builders runs without a session check and without a CSRF check,
// and nothing says so; on nestjs-trpc, a procedure without
// `@UseMiddlewares(...)` is the same. A procedure marked public that also
// asks for a role says two opposite things.
//
// Stopped by: auth-trpc src/describe-procedures.ts (`assertProceduresGuarded`
//   fails on a procedure with no access rule, and on one marked public that
//   asks for a session) and src/middlewares.ts (`AuthGuardMiddleware` closes
//   every nestjs-trpc procedure whose meta does not say `auth: 'public'`, and
//   a role or fresh-auth check on a public one refuses every call).
// Learn: Build, "Use with tRPC" (/auth/build/trpc/)
import { initTRPC, lazy } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import {
  AuthGuardMiddleware,
  assertProceduresGuarded,
  createAuthMiddlewares,
  describeProcedures,
  FreshAuthMiddleware,
  RoleMiddleware,
  type AuthState,
} from '../../src';
import { buildRouter, makeAuth } from '../support';

describe('A034 procedure left open', () => {
  const t = initTRPC.context<{ auth: AuthState }>().create();
  const { publicProcedure, protectedProcedure, role, csrf } = createAuthMiddlewares(t);

  it('names a procedure built without an access rule, and one that says two things', () => {
    const router = t.router({
      open: publicProcedure.query(() => 1),
      closed: protectedProcedure.query(() => 1),
      admin: protectedProcedure.use(role('admin')).query(() => 1),
      forgotten: t.procedure.query(() => 1),
      csrfOnly: t.procedure.use(csrf).mutation(() => 1),
      confused: publicProcedure.use(role('admin')).query(() => 1),
    });

    expect(describeProcedures(router).map((p) => [p.path, p.access, p.conflicting])).toEqual([
      ['open', 'public', false],
      ['closed', 'session', false],
      ['admin', 'session', false],
      ['forgotten', 'open', false],
      ['csrfOnly', 'open', false],
      ['confused', 'session', true],
    ]);

    expect(() => assertProceduresGuarded(router)).toThrow(
      /forgotten: no access rule[\s\S]*csrfOnly: no access rule[\s\S]*confused: marked public/u,
    );

    const withLazy = t.router({ later: lazy(async () => Promise.resolve(t.router({}))) });

    expect(() => assertProceduresGuarded(withLazy)).toThrow(/later: a lazy router/u);
  });

  it('passes the documented router', () => {
    expect(() => assertProceduresGuarded(buildRouter(makeAuth().auth))).not.toThrow();
  });

  it('refuses a nestjs-trpc context it did not build, and public with a role or fresh proof', async () => {
    const ctx = { auth: {} };
    const next = () => Promise.resolve('ran');

    // Not a context from createAuthContext: refused, never let through.
    await expect(new AuthGuardMiddleware().use({ ctx, type: 'query', next })).rejects.toThrow(
      /createAuthContext/u,
    );

    const publicMeta = { ctx, type: 'query', meta: { auth: 'public' }, next };

    await expect(new (RoleMiddleware('admin'))().use(publicMeta)).rejects.toThrow(
      /cannot also require a role/u,
    );

    await expect(new (FreshAuthMiddleware())().use(publicMeta)).rejects.toThrow(
      /cannot also require a fresh credential proof/u,
    );
  });
});
