/**
 * The module that wires the core into a Nest app with the dangerous parts
 * done by default:
 *
 * - the `createAuth` result under the `AUTH` token;
 * - `SessionGuard` as a global guard, so every route needs a session unless it
 *   carries `@Public()` (there is no switch to turn it off);
 * - `CsrfMiddleware` on every route, which runs before any guard;
 * - `SessionCookies` for the controllers that sign people in and out.
 *
 * The module is global, so the guard, the decorators and `AUTH` work in every
 * feature module without importing it again.
 */
import {
  Module,
  RequestMethod,
  type DynamicModule,
  type InjectionToken,
  type MiddlewareConsumer,
  type ModuleMetadata,
  type NestModule,
  type OptionalFactoryDependency,
  type Provider,
} from '@nestjs/common';
import { APP_GUARD, DiscoveryModule } from '@nestjs/core';
import type { AuthUser } from '@noctcore/auth';
import { CsrfMiddleware } from './csrf.middleware';
import { resolveOptions, type AuthModuleOptions, type ResolvedOptions } from './options';
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

@Module({})
export class AuthModule implements NestModule {
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

  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CsrfMiddleware).forRoutes({ path: '{*splat}', method: RequestMethod.ALL });
  }
}
