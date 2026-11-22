/**
 * A procedure nobody marked must not be open.
 *
 * tRPC has no global guard: a procedure built on `t.procedure` instead of
 * `publicProcedure` or `protectedProcedure` runs with no session check and no
 * CSRF check, and nothing says so. `describeProcedures(router)` lists every
 * procedure of a plain tRPC router with the access rule its middlewares give
 * it, and `assertProceduresGuarded(router)` throws when one has none, so a
 * test (or the boot) fails instead of the endpoint shipping open.
 *
 * It also refuses a procedure marked public that asks for a session, a role
 * or a fresh proof: the two say opposite things, and which one was meant is
 * not something to guess. And it refuses `writesCookies` on a procedure that
 * is not a mutation, which the middleware would refuse on every call anyway:
 * this way the test (or the boot) says so first.
 *
 * For nestjs-trpc, register `AuthGuardMiddleware` in `globalMiddlewares`
 * instead: it is closed unless a procedure's meta says `auth: 'public'`.
 */
import { AuthConfigError } from '@noctcore/auth';
import type { AnyRouter } from '@trpc/server';
import { kindOf } from './middlewares';

export interface ProcedureAccess {
  readonly path: string;
  readonly type: string;
  /** `session` behind `authed`, `freshAuth` or `role`; `public` behind `publicProcedure`; `open` otherwise. */
  readonly access: 'session' | 'public' | 'open';
  /** True when the procedure is marked public and also asks for a session. */
  readonly conflicting: boolean;
  /** True when the procedure carries `writesCookies`. */
  readonly writesCookies: boolean;
}

interface ProcedureLike {
  readonly _def: { readonly type: string; readonly middlewares: readonly unknown[] };
}

export function describeProcedures(router: AnyRouter): ProcedureAccess[] {
  const procedures = (
    router._def as unknown as { readonly procedures: Readonly<Record<string, ProcedureLike>> }
  ).procedures;

  return Object.entries(procedures).map(([path, procedure]) => {
    const found = new Set(procedure._def.middlewares.map(kindOf));
    const session = found.has('session');
    const open = found.has('public');

    return {
      path,
      type: procedure._def.type,
      access: session ? 'session' : open ? 'public' : 'open',
      conflicting: session && open,
      writesCookies: found.has('cookies'),
    };
  });
}

/**
 * Throws an `AuthConfigError` naming every procedure with no access rule,
 * every one marked public that also asks for a session, every one that is
 * not a mutation and carries `writesCookies`, and every lazy router (which
 * this cannot load to check).
 */
export function assertProceduresGuarded(router: AnyRouter): void {
  const lazy = Object.keys((router._def as unknown as { lazy: object }).lazy);

  const lines = [
    ...describeProcedures(router).flatMap((p) => [
      ...(p.access === 'open'
        ? [`${p.path}: no access rule; build it on publicProcedure or protectedProcedure`]
        : []),
      ...(p.conflicting
        ? [`${p.path}: marked public but asks for a session, a role or a fresh proof`]
        : []),
      ...(p.writesCookies && p.type !== 'mutation'
        ? [`${p.path}: writesCookies on a ${p.type}; write cookies from a mutation`]
        : []),
    ]),
    ...lazy.map((path) => `${path}: a lazy router this check cannot load; check it on its own`),
  ];

  if (lines.length > 0) {
    throw new AuthConfigError(
      `Every procedure needs one access rule, and only a mutation can write cookies:\n${lines.join('\n')}`,
    );
  }
}
