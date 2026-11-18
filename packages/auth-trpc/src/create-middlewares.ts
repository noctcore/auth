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
import type { AuthUser, Duration } from '@noctcore/auth';
import type {
  TRPCMiddlewareBuilder,
  TRPCProcedureBuilder,
  TRPCUnsetMarker as Unset,
} from '@trpc/server';
import type { AuthState, AuthWriter } from './context';
import type { TrpcAuth } from './options';
import {
  authedBody,
  csrfBody,
  freshAuthBody,
  pickRateLimitRule,
  publicBody,
  rateLimitedBody,
  resolveRateLimitTiers,
  writesCookiesBody,
  roleBody,
  type MiddlewareCall,
  type Principal,
  type TrpcRateLimitRule,
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

/** What `writesCookies` puts in place of `ctx.auth`: the same state, with the cookie writers. */
type WriterOf<TContext> =
  TContext extends AuthContext<infer U, infer A>
    ? { auth: AuthWriter<U, A> }
    : { auth: AuthWriter };

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

/** The second argument of `createAuthMiddlewares`. */
export interface AuthMiddlewareOptions<TTier extends string = string> {
  /**
   * Named rate limits, checked when the middlewares are made. A procedure
   * picks one with `rateLimited(name, 'tier')`, or with `rateLimited('tier')`
   * to share that tier's budget with every procedure that does the same. A
   * tier named `default` replaces the 10 a minute of `rateLimited(name)`.
   */
  readonly rateLimits?: Readonly<Record<TTier, TrpcRateLimitRule>>;
}

export interface AuthMiddlewares<TContext, TMeta, TErrorShape, TTier extends string = never> {
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
   * A fixed window under `trpc:<name>` (429 `rate_limited`), per client IP
   * unless the rule says `keyBy: 'user'`. The rule is `rule` when given (a
   * tier name, or a rule of its own), else the tier named `name`, else the
   * `default` tier, else 10 a minute. Skipped on a procedure whose meta says
   * `rateLimit: 'exempt'`. Refuses when the counter store is down.
   */
  rateLimited(
    name: string,
    rule?: TrpcRateLimitRule | TTier,
  ): TRPCMiddlewareBuilder<TContext, TMeta, object, unknown>;
  /**
   * The only way to the cookie writers: after it, `ctx.auth` is an
   * `AuthWriter` with `setSession`, `signOut` and `clearSession`; without
   * it they are not on the type and refuse at run time. On a streamed batch
   * (`httpBatchStreamLink`), whose headers are already sent, it refuses
   * before the procedure runs, so a sign-in or a rotation never happens
   * without its cookie.
   */
  readonly writesCookies: TRPCMiddlewareBuilder<TContext, TMeta, WriterOf<TContext>, unknown>;
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
  TTier extends string = never,
>(
  t: AuthRoot<TContext, TMeta, TErrorShape>,
  options: AuthMiddlewareOptions<TTier> = {},
): AuthMiddlewares<TContext, TMeta, TErrorShape, TTier> {
  // tRPC types each middleware body by the root object's context; the shared
  // bodies take the plain call, so the root is read untyped here and the
  // result is typed by the interface above.
  const root = t as unknown as UntypedRoot;
  const make = (body: Body) => root.middleware(body) as never;
  const authed = make(authedBody);
  const tiers = resolveRateLimitTiers(options.rateLimits);

  return {
    csrf: make(csrfBody),
    authed,
    freshAuth: (maxAge) => make(freshAuthBody(maxAge)),
    role: (...roles) => make(roleBody(roles)),
    rateLimited: (name, rule) => make(rateLimitedBody(name, pickRateLimitRule(tiers, name, rule))),
    writesCookies: make(writesCookiesBody),
    publicProcedure: root.procedure.use(make(publicBody)) as never,
    protectedProcedure: root.procedure.use(authed) as never,
  };
}
