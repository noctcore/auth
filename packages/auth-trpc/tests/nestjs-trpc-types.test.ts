// Type tests: the nestjs-trpc classes fit nestjs-trpc's own middleware type
// under `strict`, with no cast, wherever a consumer registers them.
// `bun run typecheck` checks them; the runtime part only keeps Vitest happy.
//
// nestjs-trpc types `globalMiddlewares` and `@UseMiddlewares` through
// type-fest, which it lists only as a dev dependency. Without type-fest
// installed those types fall back to `any` and accept anything, so this
// package keeps type-fest as a dev dependency to check them for real.
import 'reflect-metadata';
import { Module } from '@nestjs/common';
import { Query, Router, TRPCModule, UseMiddlewares, type TRPCMiddleware } from 'nestjs-trpc';
import { describe, expectTypeOf, it } from 'vitest';
import {
  AuthedMiddleware,
  AuthGuardMiddleware,
  CsrfMiddleware,
  FreshAuthMiddleware,
  RateLimitMiddleware,
  RoleMiddleware,
  WritesCookiesMiddleware,
} from '../src';

type TrpcMiddlewareClass = new () => TRPCMiddleware;

const AdminOnly = RoleMiddleware('admin');
const Fresh = FreshAuthMiddleware('1m');
const Limited = RateLimitMiddleware('types-ping', { limit: 1, window: '1m' });

@Router({ alias: 'typed' })
@UseMiddlewares(CsrfMiddleware)
class TypedRouter {
  @UseMiddlewares(WritesCookiesMiddleware, CsrfMiddleware)
  @Query()
  ping() {
    return 1;
  }

  @UseMiddlewares(AuthedMiddleware, AdminOnly, Fresh, Limited)
  @Query()
  admin() {
    return 2;
  }
}

@Module({
  imports: [
    TRPCModule.forRoot({
      globalMiddlewares: [AuthGuardMiddleware, CsrfMiddleware, WritesCookiesMiddleware],
    }),
  ],
  providers: [TypedRouter, AuthGuardMiddleware, CsrfMiddleware, WritesCookiesMiddleware],
})
class TypedModule {}

describe('nestjs-trpc middleware types', () => {
  it('assigns every class to the TRPCMiddleware constructor type', () => {
    const csrf: TrpcMiddlewareClass = CsrfMiddleware;
    const writesCookies: TrpcMiddlewareClass = WritesCookiesMiddleware;
    const instance: TRPCMiddleware = new CsrfMiddleware();

    expectTypeOf(CsrfMiddleware).toExtend<TrpcMiddlewareClass>();
    expectTypeOf(WritesCookiesMiddleware).toExtend<TrpcMiddlewareClass>();
    expectTypeOf(AuthGuardMiddleware).toExtend<TrpcMiddlewareClass>();
    expectTypeOf(AuthedMiddleware).toExtend<TrpcMiddlewareClass>();
    expectTypeOf(AdminOnly).toExtend<TrpcMiddlewareClass>();
    expectTypeOf(Fresh).toExtend<TrpcMiddlewareClass>();
    expectTypeOf(Limited).toExtend<TrpcMiddlewareClass>();

    void [csrf, writesCookies, instance, TypedModule];
  });
});
