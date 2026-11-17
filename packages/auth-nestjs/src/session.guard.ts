/**
 * The session guard, registered globally by `AuthModule`. Closed by default:
 * a route without `@Public()` answers 401 unless the request carries a session
 * the core accepts and whose user still exists.
 *
 * Order, on every route:
 *
 * 1. the session, through the core only (`validateRequest`), shared with the
 *    CSRF middleware so it is validated once;
 * 2. the user, loaded from the store on this request, so a deleted user is
 *    signed out at once and roles are never read from a cookie or token;
 * 3. `@RequireRole()`, only after both of the above;
 * 4. `@RequireFreshAuth()`.
 *
 * A refusal carries a fixed body naming only the public error code: never the
 * session id, the token or the user's email.
 */
import {
  HttpException,
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthConfigError, type AuthErrorCode, type AuthUser } from '@noctcore/auth';
import type { ResolvedOptions } from './options';
import { rawRequest, sessionState, setPrincipal } from './request';
import { AUTH_OPTIONS, FRESH_AUTH_KEY, PUBLIC_KEY, ROLES_KEY } from './tokens';

function refuse(status: number, code: AuthErrorCode): HttpException {
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
    // Only HTTP requests carry a session cookie; other transports are the app's call.
    if (context.getType() !== 'http') return true;

    const targets: Target[] = [context.getHandler(), context.getClass()];
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(PUBLIC_KEY, targets);
    const req = rawRequest(context.switchToHttp().getRequest());
    const state = await sessionState(req, this.options);

    const user = state.session
      ? await this.options.auth.context.users.findById(state.session.userId)
      : null;

    const session = user ? state.session : null;

    setPrincipal(req, { ...state, session, user });

    if (isPublic === true) return true;
    if (!session || !user) throw refuse(401, 'session_expired');

    for (const target of targets) await this.checkRoles(target, user);

    for (const target of targets) this.checkFreshness(target, session);

    return true;
  }

  private async checkRoles(target: Target, user: AuthUser): Promise<void> {
    const required = this.reflector.get<readonly string[] | undefined>(ROLES_KEY, target);

    if (required === undefined) return;

    if (!this.options.roles) {
      throw new AuthConfigError('@RequireRole() needs the `roles` option of AuthModule');
    }

    const roles = await this.options.roles(user);

    if (!required.some((role) => roles.includes(role))) throw refuse(403, 'forbidden');
  }

  private checkFreshness(
    target: Target,
    session: NonNullable<Awaited<ReturnType<typeof sessionState>>['session']>,
  ): void {
    const maxAge = this.reflector.get<number | true | undefined>(FRESH_AUTH_KEY, target);

    if (maxAge === undefined) return;

    const { auth } = this.options;
    const fresh = auth.requireFreshAuth(session);

    const withinMaxAge =
      maxAge === true || auth.context.clock.now() - session.authenticatedAt <= maxAge;

    if (!fresh.ok || !withinMaxAge) throw refuse(403, 'fresh_auth_required');
  }
}
