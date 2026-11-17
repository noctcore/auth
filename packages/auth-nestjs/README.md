> **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

# @noctcore/auth-nestjs

A NestJS module for [`@noctcore/auth`](https://github.com/noctcore/auth): a session guard that is closed by default, CSRF middleware that runs before any guard, decorators for the current user and session, and a trust-proxy setup that refuses to guess in production.

```ts
import { Module } from '@nestjs/common';
import { AuthModule, trustedHopsFromEnv } from '@noctcore/auth-nestjs';

@Module({
  imports: [
    AuthModule.forRoot({
      auth, // the createAuth(...) result
      trustedHops: trustedHopsFromEnv(process.env),
      csrf: { secrets: [process.env.CSRF_SECRET], allowedOrigins: ['https://app.example'] },
      roles: (user) => [user.role],
    }),
  ],
})
export class AppModule {}
```

- **Closed by default.** `SessionGuard` is registered globally and refuses every route without a valid session (401) unless the route or its controller carries `@Public()`. It validates the session through the core only and loads the user from your store on every request.
- **CSRF before any guard.** On every unsafe method the `Origin` must be allowed, `Sec-Fetch-Site` must say `same-origin` when sent, and the double-submit token must be bound to this session or pre-session. A refusal is a 403 with one fixed body, answered by the middleware itself, and the guard refuses any unsafe request the middleware did not see (Nest versions differ in which routes reach a middleware). `csrf.exempt` lists paths (a webhook) that skip it.
- **Decorators.** `@CurrentUser()`, `@CurrentSession()` and `@AuthMeta()` (the `RequestMeta` for the flows); `@RequireRole(...)`, read fresh on every request; `@RequireFreshAuth(maxAge?)`, which can only shorten the core's `freshAuthAge`.
- **Cookies.** `SessionCookies.set(res, issued)` writes a new session with a CSRF token bound to it (sign-in and every rotation); `SessionCookies.signOut(req, res)` ends one.
- **Trust proxy.** `trustedHopsFromEnv` reads `TRUST_PROXY` as a hop count counted from the right, refuses `true` and counts above 16, and refuses an unset value in production. `configureTrustProxy(app, process.env)` sets Express's `trust proxy` to the same count.
- **A compile test.** `describeRoutes(app)` lists every route with its rule, so a test can boot the whole app and pin the routes open without a session.

- **Contradictions refused at boot.** A route that is `@Public()` and also requires a role or fresh auth, or uses `@RequireRole()` without the `roles` option, stops the app at startup with the route's name.

Needs NestJS 11 or 12 on the Express platform, and `experimentalDecorators` in your `tsconfig.json`. HTTP controllers only: GraphQL resolvers, WebSocket gateways and microservice handlers are not supported yet and are refused unless `@Public()`. Fastify is not supported yet.

The guide, with the guard order and the trust-proxy rule: [Use with NestJS](https://noctcore.github.io/auth/build/nestjs/). A full app with its tests: [`examples/nestjs`](https://github.com/noctcore/auth/tree/main/examples/nestjs).
