# @noctcore/auth-nestjs

## 0.3.0

### Minor Changes

- [#52](https://github.com/noctcore/auth/pull/52) [`291ebee`](https://github.com/noctcore/auth/commit/291ebeebe7a0a0a717efe88de8dfd9071d65cebf) Thanks [@Shironex](https://github.com/Shironex)! - Add `@noctcore/auth-nestjs`, the NestJS module: `AuthModule.forRoot` and `forRootAsync` provide the `createAuth` result under `AUTH`, register `SessionGuard` globally (closed by default, `@Public()` opens a route) and run `CsrfMiddleware` before every route (Origin allowlist, `Sec-Fetch-Site`, and a signed double-submit token bound to the session or a pre-session id; a refusal is a 403 with a fixed body). `@CurrentUser()`, `@CurrentSession()` and `@AuthMeta()` read what the guard resolved; `@RequireRole()` reads roles fresh on every request and `@RequireFreshAuth(maxAge?)` can only shorten `freshAuthAge`. `SessionCookies` writes a new or ended session with its CSRF token. `trustedHopsFromEnv` and `configureTrustProxy` count proxy hops from the right and refuse to start in production without `TRUST_PROXY`. `describeRoutes` lists every route with its access rule for a compile test. NestJS 11 and 12, Express.

### Patch Changes

- Updated dependencies [[`ceaae4c`](https://github.com/noctcore/auth/commit/ceaae4c11e265c833e34375e829cf34205cb07a5)]:
  - @noctcore/auth@0.3.0
