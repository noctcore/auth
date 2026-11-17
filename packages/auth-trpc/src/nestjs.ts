/**
 * The same middlewares as nestjs-trpc classes, running the very bodies plain
 * tRPC runs (`middlewares.ts`).
 *
 * nestjs-trpc resolves each class in `@UseMiddlewares(...)` from the Nest
 * container and calls its `use(opts)`. None of these classes has a
 * constructor dependency, so they need no decorator: list each one in a
 * module's `providers`. The parameterised ones are made by a function, once,
 * at module level:
 *
 * ```ts
 * const AdminOnly = RoleMiddleware('admin');
 * ```
 *
 * The context class must return `createAuthContext(...).node(opts)` (spread
 * into your own context if you add to it).
 */
import type { Duration, RateLimitRule } from '@noctcore/auth';
import {
  authedBody,
  csrfBody,
  freshAuthBody,
  guardBody,
  rateLimitedBody,
  writesCookiesBody,
  roleBody,
  type MiddlewareCall,
} from './middlewares';

/** A nestjs-trpc middleware: the shape `@UseMiddlewares` accepts. */
export interface NestTrpcMiddleware {
  use<TResult>(opts: MiddlewareCall<TResult> & { readonly meta?: unknown }): Promise<TResult>;
}

export type NestTrpcMiddlewareClass = new () => NestTrpcMiddleware;

type Body = <TResult>(
  call: MiddlewareCall<TResult> & { readonly meta?: unknown },
) => Promise<TResult>;

function middlewareClass(body: Body): NestTrpcMiddlewareClass {
  return class implements NestTrpcMiddleware {
    use<TResult>(opts: MiddlewareCall<TResult> & { readonly meta?: unknown }): Promise<TResult> {
      return body(opts);
    }
  };
}

/**
 * The default to put in `globalMiddlewares`: CSRF on every mutation, and a
 * session on every procedure unless its meta says `auth: 'public'`
 * (`@Mutation({ meta: { auth: 'public' } })`). Closed when nobody marked it.
 */
export const AuthGuardMiddleware: NestTrpcMiddlewareClass = middlewareClass(guardBody);

/** Refuses a mutation that fails the CSRF checks. */
export const CsrfMiddleware: NestTrpcMiddlewareClass = middlewareClass(csrfBody);

/** Refuses a forged mutation, then a caller without a valid session; adds `user` and `session`. */
export const AuthedMiddleware: NestTrpcMiddlewareClass = middlewareClass(authedBody);

/**
 * Requires a recent credential proof; `maxAge` can only shorten `freshAuthAge`.
 * Refused as a configuration error on a procedure whose meta says `auth: 'public'`.
 */
export const FreshAuthMiddleware = (maxAge?: Duration): NestTrpcMiddlewareClass =>
  middlewareClass(freshAuthBody(maxAge));

/**
 * Requires at least one of `roles`, read through the `roles` option on every
 * call. Refused as a configuration error on a procedure whose meta says
 * `auth: 'public'`.
 */
export const RoleMiddleware = (...roles: readonly string[]): NestTrpcMiddlewareClass =>
  middlewareClass(roleBody(roles));

/** A fixed window per client IP under `trpc:<name>`; refuses when the counter store is down. */
export const RateLimitMiddleware = (name: string, rule?: RateLimitRule): NestTrpcMiddlewareClass =>
  middlewareClass(rateLimitedBody(name, rule));

/**
 * For every procedure that writes cookies: refuses it on a streamed batch
 * (`httpBatchStreamLink`) before the flow runs.
 */
export const WritesCookiesMiddleware: NestTrpcMiddlewareClass = middlewareClass(writesCookiesBody);
