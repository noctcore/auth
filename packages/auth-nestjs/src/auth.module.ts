/**
 * The module that wires the core into a Nest app with the dangerous parts
 * done by default:
 *
 * - the `createAuth` result under the `AUTH` token;
 * - `SessionGuard` as a global guard, so every route needs a session unless it
 *   carries `@Public()` (there is no switch to turn it off);
 * - `CsrfMiddleware` on every route, which runs before any guard;
 * - `SessionCookies` for the controllers that sign people in and out;
 * - `auth.flush()` on shutdown (`beforeApplicationShutdown`), so mail sends
 *   still in flight finish before your `onApplicationShutdown` hooks close the
 *   database and Redis connections. Nest runs it on `app.close()`, and on
 *   SIGTERM once you call `app.enableShutdownHooks()`. The wait is bounded by
 *   `shutdownTimeout` (10 seconds by default); what is still running then is
 *   logged and abandoned.
 *
 * The module is global, so the guard, the decorators and `AUTH` work in every
 * feature module without importing it again.
 */
import {
  Inject,
  Module,
  type BeforeApplicationShutdown,
  RequestMethod,
  type DynamicModule,
  type InjectionToken,
  type MiddlewareConsumer,
  type ModuleMetadata,
  type NestModule,
  type OnModuleInit,
  type OptionalFactoryDependency,
  type Provider,
} from '@nestjs/common';
import { APP_GUARD, DiscoveryModule, DiscoveryService, Reflector } from '@nestjs/core';
import { AuthConfigError, type AuthUser } from '@noctcore/auth';
import { CsrfMiddleware } from './csrf.middleware';
import { resolveOptions, type AuthModuleOptions, type ResolvedOptions } from './options';
import { collectRoutes, type RouteAccess } from './routes';
import { SessionCookies } from './session-cookies';
import { SessionGuard } from './session.guard';
import { AUTH, AUTH_OPTIONS } from './tokens';

export interface AuthModuleAsyncOptions<U extends AuthUser = AuthUser> extends Pick<
  ModuleMetadata,
  'imports'
> {
  readonly useFactory: (...args: never[]) => AuthModuleOptions<U> | Promise<AuthModuleOptions<U>>;
  readonly inject?: readonly (InjectionToken | OptionalFactoryDependency)[];
}

const shared: Provider[] = [
  { provide: AUTH, useFactory: (options: ResolvedOptions) => options.auth, inject: [AUTH_OPTIONS] },
  { provide: APP_GUARD, useClass: SessionGuard },
  SessionGuard,
  SessionCookies,
  CsrfMiddleware,
];

const exported = [AUTH, AUTH_OPTIONS, SessionGuard, SessionCookies, CsrfMiddleware];

/** What is wrong with a route's access rule, or null when nothing is. */
function misconfiguration(route: RouteAccess, options: ResolvedOptions): string | null {
  const name = `${route.controller}.${route.handler} (${route.method} ${route.path})`;

  if (route.public && (route.roles.length > 0 || route.freshAuth)) {
    return `${name} is @Public() and also requires a role or fresh auth; a public route has no session to check, so remove one of them`;
  }

  if (route.roles.length > 0 && !options.roles) {
    return `${name} uses @RequireRole() but AuthModule has no \`roles\` option`;
  }

  return null;
}

@Module({})
export class AuthModule implements NestModule, OnModuleInit, BeforeApplicationShutdown {
  constructor(
    @Inject(DiscoveryService) private readonly discovery: DiscoveryService,
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(AUTH_OPTIONS) private readonly options: ResolvedOptions,
  ) {}

  static forRoot<U extends AuthUser>(options: AuthModuleOptions<U>): DynamicModule {
    return {
      module: AuthModule,
      global: true,
      imports: [DiscoveryModule],
      providers: [{ provide: AUTH_OPTIONS, useValue: resolveOptions(options) }, ...shared],
      exports: exported,
    };
  }

  static forRootAsync<U extends AuthUser>(options: AuthModuleAsyncOptions<U>): DynamicModule {
    const factory = options.useFactory as (
      ...args: unknown[]
    ) => AuthModuleOptions<U> | Promise<AuthModuleOptions<U>>;

    return {
      module: AuthModule,
      global: true,
      imports: [DiscoveryModule, ...(options.imports ?? [])],
      providers: [
        {
          provide: AUTH_OPTIONS,
          useFactory: async (...args: unknown[]) => resolveOptions(await factory(...args)),
          inject: [...(options.inject ?? [])],
        },
        ...shared,
      ],
      exports: exported,
    };
  }

  /**
   * Refuses to boot on a route whose decorators contradict each other, such
   * as `@Public()` on a controller and `@RequireRole()` on one of its
   * handlers, instead of leaving it to the guard to pick one at request time.
   */
  async beforeApplicationShutdown(): Promise<void> {
    // Bounded: a send that never settles must not keep `app.close()` (or
    // SIGTERM) from finishing. Whatever is left is logged by the core.
    await this.options.auth.flush?.({ timeout: this.options.shutdownTimeout });
  }

  onModuleInit(): void {
    const problems = collectRoutes(this.discovery, this.reflector)
      .map((route) => misconfiguration(route, this.options))
      .filter((problem): problem is string => problem !== null);

    if (problems.length > 0) throw new AuthConfigError(problems.join('\n'));
  }

  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CsrfMiddleware).forRoutes({ path: '{*splat}', method: RequestMethod.ALL });
  }
}
