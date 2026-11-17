/**
 * @noctcore/auth-nestjs: a NestJS module for @noctcore/auth.
 *
 * - `AuthModule.forRoot` / `forRootAsync` provide the `createAuth` result under
 *   `AUTH`, register `SessionGuard` globally (closed by default, `@Public()` to
 *   open a route) and run `CsrfMiddleware` before every route.
 * - `@CurrentUser()`, `@CurrentSession()` and `@AuthMeta()` read what the guard
 *   resolved; `@RequireRole()` and `@RequireFreshAuth()` narrow a route.
 * - `SessionCookies` writes a new or ended session with its CSRF token.
 * - `configureTrustProxy` and `trustedHopsFromEnv` read `TRUST_PROXY` and refuse
 *   to start in production without it.
 * - `describeRoutes` lists every route with its access rule, for a test.
 *
 * Express is the supported platform.
 */
export { AuthModule, type AuthModuleAsyncOptions } from './auth.module';
export { CsrfMiddleware } from './csrf.middleware';
export {
  AuthMeta,
  CurrentSession,
  CurrentUser,
  Public,
  RequireFreshAuth,
  RequireRole,
} from './decorators';
export type { AuthModuleOptions, CsrfOptions, NestAuth } from './options';
export { describeRoutes, type RouteAccess } from './routes';
export { SessionCookies } from './session-cookies';
export { SessionGuard } from './session.guard';
export { AUTH } from './tokens';
export { configureTrustProxy, trustedHopsFromEnv, type TrustProxyEnv } from './trust-proxy';
