---
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

Both adapters can now validate a request without counting it as activity, so a page that polls on a timer no longer keeps an idle session alive for its whole absolute lifetime. The default is unchanged: every request touches.

- NestJS: a new `touch` option on `AuthModule`, `true`, `false` or a predicate `(request) => boolean` over the request's method, path (a global prefix included, no query string) and headers. It runs before the one validation of the request. A request it marks passive is answered with its session and leaves `lastActiveAt` alone. New exported type `TouchRequest`.
- tRPC: a new `touch` option on `createAuthContext`, `true`, `false` or a predicate `(path) => boolean` asked about each procedure path of the request, and a procedure meta `touch: false` (on `AuthProcedureMeta`). Both are read from the calls tRPC parsed before it built the context. A batch touches when any of its procedures is active, and a request whose adapter names no calls touches as before.
- The CSRF checks and the guards' decisions do not change with the option, and the session is still validated once per request.
