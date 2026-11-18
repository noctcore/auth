/**
 * The session guard, registered globally by `AuthModule`. Closed by default:
 * a route without `@Public()` answers 401 unless the request carries a session
 * the core accepts and whose user still exists.
 *
 * Order, on every route:
 *
 * 0. an unsafe method must have passed `CsrfMiddleware` (or been exempted by
 *    it). Which routes Nest hands to a middleware depends on its version and
 *    on the global prefix, so the guard does not trust that mapping: an
 *    unsafe request the middleware never saw is refused with its fixed 403;
 * 1. the session, through the core only (`validateRequest`), shared with the
 *    CSRF middleware so it is validated once;
 * 2. the user, loaded from the store on this request, so a deleted user is
 *    signed out at once and roles are never read from a cookie or token;
 * 3. `@RequireRole()`, only after both of the above;
 * 4. `@RequireFreshAuth()`.
 *
 * `@Public()` lets a request through without a session, and skips steps 3
 * and 4, only on a route with no role or fresh-auth requirement; a route with
 * one always needs a session (and `AuthModule` refuses to boot with such a
 * route, so the mistake is caught early). Steps 1 and 2 still run on a public
 * route: a session the request carries is resolved and its user loaded, so
 * `@CurrentSession()` and `@CurrentUser()` name the caller when there is one.
 * Flows that refuse another account's session (an email verification link, for
 * one) depend on that.
 *
 * Only HTTP is supported. A GraphQL resolver, a WebSocket gateway or a
 * microservice handler is refused unless it is `@Public()`, so a transport
 * the module cannot read a session from never gets through by accident.
 *
 * A refusal carries a fixed body naming only the public error code: never the
 * session id, the token or the user's email. A store failure is logged by its
 * error name only and answered with a fixed 500.
 */
import {
  HttpException,
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { AuthErrorCode, AuthUser, StoredSession } from '@noctcore/auth';
import { isSafeMethod } from './csrf-tokens';
import type { ResolvedOptions } from './options';
import { csrfPassed, rawRequest, sessionState, setPrincipal, type RawRequest } from './request';
import { AUTH_OPTIONS, FRESH_AUTH_KEY, PUBLIC_KEY, ROLES_KEY } from './tokens';

function refuse(status: number, code: AuthErrorCode | 'internal'): HttpException {
  return new HttpException({ error: { code } }, status);
}

type Target = ReturnType<ExecutionContext['getHandler']> | ReturnType<ExecutionContext['getClass']>;

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(AUTH_OPTIONS) private readonly options: ResolvedOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets: Target[] = [context.getHandler(), context.getClass()];
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(PUBLIC_KEY, targets);

    const requirements = targets.some(
      (target) =>
        this.reflector.get(ROLES_KEY, target) !== undefined ||
        this.reflector.get(FRESH_AUTH_KEY, target) !== undefined,
    );

    const open = isPublic === true && !requirements;

    if (context.getType() !== 'http') return open;

    const req = rawRequest(context.switchToHttp().getRequest());

    if (!isSafeMethod(req.method ?? 'GET') && !csrfPassed(req)) throw refuse(403, 'forbidden');

    try {
      return await this.check(req, targets, open);
    } catch (error) {
      if (error instanceof HttpException) throw error;

      // Only the error's name: a store error can carry the session key.
      this.options.auth.context.logger.error('Session guard could not check the request', {
        error: error instanceof Error ? error.name : typeof error,
      });

      throw refuse(500, 'internal');
    }
  }

  private async check(req: RawRequest, targets: readonly Target[], open: boolean) {
    const state = await sessionState(req, this.options);

    const user = state.session
      ? await this.options.auth.context.users.findById(state.session.userId)
      : null;

    const session = user ? state.session : null;

    setPrincipal(req, { ...state, session, user });

    if (open) return true;
    if (!session || !user) throw refuse(401, 'session_expired');

    for (const target of targets) await this.checkRoles(target, user);

    for (const target of targets) this.checkFreshness(target, session);

    return true;
  }

  private async checkRoles(target: Target, user: AuthUser): Promise<void> {
    const required = this.reflector.get<readonly string[] | undefined>(ROLES_KEY, target);

    if (required === undefined) return;

    // AuthModule refuses to boot with @RequireRole() and no `roles` option;
    // should one slip through anyway, the user has no roles.
    const roles = this.options.roles ? await this.options.roles(user) : [];

    if (!required.some((role) => roles.includes(role))) throw refuse(403, 'forbidden');
  }

  private checkFreshness(target: Target, session: StoredSession<unknown>): void {
    const maxAge = this.reflector.get<number | true | undefined>(FRESH_AUTH_KEY, target);

    if (maxAge === undefined) return;

    const { auth } = this.options;
    const fresh = auth.requireFreshAuth(session);

    const withinMaxAge =
      maxAge === true || auth.context.clock.now() - session.authenticatedAt <= maxAge;

    if (!fresh.ok || !withinMaxAge) throw refuse(403, 'fresh_auth_required');
  }
}
