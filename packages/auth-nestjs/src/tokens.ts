/**
 * Injection tokens. Symbols registered with `Symbol.for`, so two copies of the
 * package in one app (an ESM and a CommonJS load) still agree on them.
 */

/** The `createAuth(...)` result, for `@Inject(AUTH)` in your own providers. */
export const AUTH: unique symbol = Symbol.for('@noctcore/auth-nestjs:auth');

/** The checked module options. Internal. */
export const AUTH_OPTIONS: unique symbol = Symbol.for('@noctcore/auth-nestjs:options');

/** Metadata keys set by the route decorators. */
export const PUBLIC_KEY = '@noctcore/auth-nestjs:public';
export const ROLES_KEY = '@noctcore/auth-nestjs:roles';
export const FRESH_AUTH_KEY = '@noctcore/auth-nestjs:fresh-auth';
