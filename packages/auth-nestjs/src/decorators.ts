/**
 * Route and parameter decorators.
 *
 * Routes are closed by default: the global `SessionGuard` refuses every route
 * without a valid session unless the route or its controller carries
 * `@Public()`. Forgetting a decorator therefore fails closed (a 401), never
 * open.
 *
 * The parameter decorators read what the guard resolved from the stored
 * session; none of them reads a cookie, a header or the body.
 */
import {
  SetMetadata,
  createParamDecorator,
  type CustomDecorator,
  type ExecutionContext,
} from '@nestjs/common';
import {
  toMilliseconds,
  type AuthUser,
  type Duration,
  type RequestMeta,
  type StoredSession,
} from '@noctcore/auth';
import { principalOf, rawRequest, type Principal } from './request';
import { FRESH_AUTH_KEY, PUBLIC_KEY, ROLES_KEY } from './tokens';

/** Lets a route, or every route of a controller, through without a session. */
export const Public = (): CustomDecorator<string> => SetMetadata(PUBLIC_KEY, true);

/**
 * Requires a session whose user has at least one of `roles`, read through the
 * module's `roles` option on every request. On a controller and a handler
 * both, each list must be satisfied.
 */
export const RequireRole = (...roles: readonly string[]): CustomDecorator<string> =>
  SetMetadata(ROLES_KEY, roles);

/**
 * Requires a recent credential proof (`auth.requireFreshAuth`, `freshAuthAge`
 * in the core's config). `maxAge` can only make it stricter: a route asking
 * for 1 minute refuses a 2 minute old proof even when `freshAuthAge` is 10.
 */
export const RequireFreshAuth = (maxAge?: Duration): CustomDecorator<string> =>
  SetMetadata(FRESH_AUTH_KEY, maxAge === undefined ? true : toMilliseconds(maxAge));

function principal(context: ExecutionContext): Principal | undefined {
  return principalOf(rawRequest(context.switchToHttp().getRequest()));
}

export const currentUser = (_data: unknown, context: ExecutionContext): AuthUser | null =>
  principal(context)?.user ?? null;

export const currentSession = (
  _data: unknown,
  context: ExecutionContext,
): StoredSession<unknown> | null => principal(context)?.session ?? null;

export const authMeta = (_data: unknown, context: ExecutionContext): RequestMeta | undefined =>
  principal(context)?.meta;

/** The signed-in user, loaded from the store on this request; null on a public route without a session. */
export const CurrentUser = createParamDecorator(currentUser);

/** The validated session; null on a public route without a session. */
export const CurrentSession = createParamDecorator(currentSession);

/** The request's `RequestMeta` (client IP through the trusted hops, user agent, origin), for the flows. */
export const AuthMeta = createParamDecorator(authMeta);
