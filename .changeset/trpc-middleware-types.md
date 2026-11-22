---
'@noctcore/auth-trpc': patch
---

The nestjs-trpc middleware classes (`AuthGuardMiddleware`, `CsrfMiddleware`, `AuthedMiddleware`, `WritesCookiesMiddleware`, and the classes `RoleMiddleware`, `FreshAuthMiddleware` and `RateLimitMiddleware` make) now fit nestjs-trpc's `TRPCMiddleware` type under `strict`, so they go in `globalMiddlewares` and `@UseMiddlewares` without a cast. Their `use` now takes `NestTrpcMiddlewareOptions`, exported by name, whose `next` takes an optional `ctx` typed as nestjs-trpc types it. Runtime behaviour is unchanged, and the package still needs no nestjs-trpc types.
