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
  type ValidatedSession,
} from '@noctcore/auth';
import { principalOf, rawRequest, type Principal } from './request';
import { FRESH_AUTH_KEY, PUBLIC_KEY, ROLES_KEY, TWO_FACTOR_ENROLLMENT_KEY } from './tokens';

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

/**
 * Marks a route (or every route of a controller) as one an `enrollment-only`
 * session may reach, under the two-factor plugin's `enforcement`: the
 * enrollment routes, and what a user needs on the way there (the factor's
 * status, re-authentication for a stale session, sign out). Every other
 * route refuses such a session with 403 `two_factor_enrollment_required`.
 * It opens nothing else: the route still needs a session, and its role and
 * fresh-auth requirements still apply.
 */
export const TwoFactorEnrollment = (): CustomDecorator<string> =>
  SetMetadata(TWO_FACTOR_ENROLLMENT_KEY, true);

function principal(context: ExecutionContext): Principal | undefined {
  return principalOf(rawRequest(context.switchToHttp().getRequest()));
}

export const currentUser = (_data: unknown, context: ExecutionContext): AuthUser | null =>
  principal(context)?.user ?? null;

export const currentSession = (
  _data: unknown,
  context: ExecutionContext,
): ValidatedSession<unknown> | null => principal(context)?.session ?? null;

export const authMeta = (_data: unknown, context: ExecutionContext): RequestMeta | undefined =>
  principal(context)?.meta;

/** The signed-in user, loaded from the store on this request; null on a public route without a session. */
export const CurrentUser = createParamDecorator(currentUser);

/**
 * The validated session; null on a public route without a session. Under the
 * two-factor plugin's `enforcement` it carries `twoFactor` (grace or
 * enrollment-only) for this request.
 */
export const CurrentSession = createParamDecorator(currentSession);

/** The request's `RequestMeta` (client IP through the trusted hops, user agent, origin), for the flows. */
export const AuthMeta = createParamDecorator(authMeta);
