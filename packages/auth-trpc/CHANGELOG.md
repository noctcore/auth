# @noctcore/auth-trpc

## 0.4.0

### Patch Changes

- Updated dependencies [[`a78168e`](https://github.com/noctcore/auth/commit/a78168e668f7add8256d44596bd29a6455f61dd1)]:
  - @noctcore/auth@0.4.0

## 0.3.0

### Minor Changes

- [#54](https://github.com/noctcore/auth/pull/54) [`8544dd8`](https://github.com/noctcore/auth/commit/8544dd802138668f127a19d2967878767fc3388b) Thanks [@Shironex](https://github.com/Shironex)! - Add `@noctcore/auth-trpc`, the tRPC adapter. `createAuthContext` checks its options at boot and builds `ctx.auth` once per request on the fetch or Node adapters: the session validated through the core, the request meta with the client IP through the trusted hops (at most 16), and `setSession`, `signOut` and `clearSession`, which write the cookies with a CSRF token bound to the new session or pre-session. `createAuthMiddlewares(t)` returns `publicProcedure` and `protectedProcedure` plus `csrf`, `authed`, `freshAuth`, `role`, `rateLimited` and `writesCookies`, the only way to the cookie writers (`setSession`, `signOut` and `clearSession` are on `ctx.auth` only after it, typed as `AuthWriter`, and refuse at run time anywhere else), which also refuses a streamed batch (detected as tRPC does, from `trpc-accept` or `Accept`) and a subscription before the flow runs; every session check also runs the CSRF check on mutations, and `rateLimited` refuses when the counter store is down. `toTRPCError` maps every `AuthErrorCode` from the public code only (an unknown code becomes `internal`), and `authErrorFormatter` never sends a stack, answers input errors with paths and issue codes, a body that does not parse and the codes `PARSE_ERROR`, `METHOD_NOT_SUPPORTED`, `UNSUPPORTED_MEDIA_TYPE`, `PAYLOAD_TOO_LARGE` and `NOT_FOUND` with a fixed message, and internal errors with `internal`. Zod 4 input and output schemas for every auth flow, with outputs that strip unknown keys. `assertProceduresGuarded` and `assertNoSecretQueries` fail on an unguarded procedure and on a query that carries a secret. For nestjs-trpc, `AuthGuardMiddleware` is closed unless a procedure's meta says `auth: 'public'`, with `WritesCookiesMiddleware`, `RoleMiddleware`, `FreshAuthMiddleware` and `RateLimitMiddleware` running the same bodies. Peers: `@trpc/server` 11.22.1 or later within 11, and `zod` 4.3 or later within 4.

### Patch Changes

- Updated dependencies [[`ceaae4c`](https://github.com/noctcore/auth/commit/ceaae4c11e265c833e34375e829cf34205cb07a5)]:
  - @noctcore/auth@0.3.0
