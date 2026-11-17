/**
 * The middlewares and base procedures for plain tRPC, built on your own
 * `initTRPC` result so they carry its context, meta and error shape.
 *
 * `publicProcedure` and `protectedProcedure` are the safe defaults: both
 * check CSRF on every mutation, and `protectedProcedure` refuses a caller
 * without a valid session. Building on `t.procedure` directly skips both, so
 * the docs build every procedure from these two, and
 * `assertProceduresGuarded(router)` fails on any procedure that has neither.
 */
import type { AuthUser, Duration, RateLimitRule } from '@noctcore/auth';
import type {
  TRPCMiddlewareBuilder,
  TRPCProcedureBuilder,
  TRPCUnsetMarker as Unset,
} from '@trpc/server';
import type { AuthState } from './context';
import type { TrpcAuth } from './options';
import {
  authedBody,
  csrfBody,
  freshAuthBody,
  publicBody,
  rateLimitedBody,
  roleBody,
  type MiddlewareCall,
  type Principal,
} from './middlewares';

/** The context the adapter needs: `ctx.auth` from `createAuthContext`. */
export interface AuthContext<U extends AuthUser = AuthUser, A = unknown> {
  readonly auth: AuthState<U, A>;
}

/**
 * The context type for a `createAuth(...)` result: `initTRPC.context<AuthContextOf<typeof auth>>()`.
 * Spread in your own fields with an intersection.
 */
export type AuthContextOf<TAuth> =
  TAuth extends TrpcAuth<infer U, infer A> ? AuthContext<U, A> : never;

/** What `authed` adds to a context: the user and session types of its `ctx.auth`. */
type PrincipalOf<TContext> =
  TContext extends AuthContext<infer U, infer A> ? Principal<U, A> : Principal;

/** A base procedure builder on your root object, with `TOverrides` added to its context. */
export type AuthProcedureBuilder<TContext, TMeta, TOverrides, TErrorShape> = TRPCProcedureBuilder<
  TContext,
  TMeta,
  TOverrides,
  Unset,
  Unset,
  Unset,
  Unset,
  false,
  TErrorShape
>;

export interface AuthMiddlewares<TContext, TMeta, TErrorShape> {
  /** Refuses a mutation that fails the CSRF checks (403 `forbidden`). */
  readonly csrf: TRPCMiddlewareBuilder<TContext, TMeta, object, unknown>;
  /**
   * Refuses a forged mutation (403 `forbidden`), then a caller without a
   * valid session (401 `session_expired`); adds `user` and `session`.
   */
  readonly authed: TRPCMiddlewareBuilder<TContext, TMeta, PrincipalOf<TContext>, unknown>;
  /**
   * Requires a recent credential proof (403 `fresh_auth_required`); runs the
   * `authed` check itself. `maxAge` can only shorten `freshAuthAge`.
   */
  freshAuth(
    maxAge?: Duration,
  ): TRPCMiddlewareBuilder<TContext, TMeta, PrincipalOf<TContext>, unknown>;
  /** Requires one of `roles` (403 `forbidden`); runs the `authed` check itself. */
  role(
    ...roles: readonly string[]
  ): TRPCMiddlewareBuilder<TContext, TMeta, PrincipalOf<TContext>, unknown>;
  /**
   * A fixed window per client IP under `trpc:<name>`, default 10 a minute
   * (429 `rate_limited`). Refuses when the counter store is down.
   */
  rateLimited(
    name: string,
    rule?: RateLimitRule,
  ): TRPCMiddlewareBuilder<TContext, TMeta, object, unknown>;
  /** Marked public: CSRF on mutations, no session needed (sign-in, sign-up, reset). */
  readonly publicProcedure: AuthProcedureBuilder<TContext, TMeta, object, TErrorShape>;
  /** CSRF on mutations and a valid session, with `ctx.user` and `ctx.session`. */
  readonly protectedProcedure: AuthProcedureBuilder<
    TContext,
    TMeta,
    PrincipalOf<TContext>,
    TErrorShape
  >;
}

type Body = <TResult>(call: MiddlewareCall<TResult>) => Promise<TResult>;

/** Your `initTRPC.context<...>().create(...)` result, as far as this reads it. */
export interface AuthRoot<
  TContext extends AuthContext<AuthUser, unknown>,
  TMeta extends object,
  TErrorShape,
> {
  readonly procedure: AuthProcedureBuilder<TContext, TMeta, object, TErrorShape>;
  readonly middleware: (fn: never) => unknown;
}

interface UntypedRoot {
  readonly procedure: { use(middleware: unknown): { use(middleware: unknown): unknown } };
  middleware(fn: Body): unknown;
}

export function createAuthMiddlewares<
  TContext extends AuthContext<AuthUser, unknown>,
  TMeta extends object,
  TErrorShape,
>(t: AuthRoot<TContext, TMeta, TErrorShape>): AuthMiddlewares<TContext, TMeta, TErrorShape> {
  // tRPC types each middleware body by the root object's context; the shared
  // bodies take the plain call, so the root is read untyped here and the
  // result is typed by the interface above.
  const root = t as unknown as UntypedRoot;
  const make = (body: Body) => root.middleware(body) as never;
  const authed = make(authedBody);

  return {
    csrf: make(csrfBody),
    authed,
    freshAuth: (maxAge) => make(freshAuthBody(maxAge)),
    role: (...roles) => make(roleBody(roles)),
    rateLimited: (name, rule) => make(rateLimitedBody(name, rule)),
    publicProcedure: root.procedure.use(make(publicBody)) as never,
    protectedProcedure: root.procedure.use(authed) as never,
  };
}
