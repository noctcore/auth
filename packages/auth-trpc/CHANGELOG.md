# @noctcore/auth-trpc

## 0.5.0

### Minor Changes

- [#64](https://github.com/noctcore/auth/pull/64) [`2ab09b7`](https://github.com/noctcore/auth/commit/2ab09b7b3769e14fbd72259138592df55a8bb3bb) Thanks [@Shironex](https://github.com/Shironex)! - Add the membership plugin, `@noctcore/auth/membership`, with flows under `auth.membership` (`add`, `changeRole`, `remove`): nobody acts on themselves (`self_target`, by user id), the last member holding an admin role in a scope can be neither demoted nor removed (`last_admin`, decided atomically by the store), the actor's right is read from the store on every call (`canManage`, default: the actor holds an admin role), and every flow first reads the acting session live from the store. Session revocation is opt-in (`revokeSessionsOnChange`, default false) for apps that copy roles into sessions: then an attempted role change to another role, or a removal, revokes every session of the member through the epoch fence (revocation reason `membership-changed`), before and after the write, so an attempt the store refuses (`last_admin`, a stale or missing target) has still revoked them, while adding a member and setting the role a member already holds never revoke. The guards fail closed. The plugin does not scope data.
  
  - New store port `MembershipStore`, with `membershipStoreConformance` and `MemoryMembershipStore` in `@noctcore/auth/testing`.
  - New public error codes `self_target` and `last_admin`. `AUTH_ERROR_TRPC_CODES` in `@noctcore/auth-trpc` maps them to `FORBIDDEN` and `CONFLICT`. Code that switches over every `AuthErrorCode` with a `never` check needs cases for them.
  - New audit event types `membership.added`, `membership.role_changed`, `membership.removed` and `membership.refused`. An audit sink that switches over every type with a `never` check needs cases for them.
  - `SessionAccess` (the plugin context's `sessions`) gains `findActive(id)`, a read of a live session by id, so a plugin can check that the session it was handed is still live. It cannot mint or re-issue anything.

- [#69](https://github.com/noctcore/auth/pull/69) [`5fde7f8`](https://github.com/noctcore/auth/commit/5fde7f814608d51aab840dc57647ed2c77bbb5bd) Thanks [@Shironex](https://github.com/Shironex)! - Only one procedure per HTTP request can write cookies. Every procedure of a tRPC batch shares `ctx.auth`, so two session-writing procedures in one batch (two sign-ins, or a sign-in and a rotation) used to both run: the browser kept the cookie written last, and the other session stayed valid with no browser holding it. Now the first procedure to reach `writesCookies` (or `WritesCookiesMiddleware` on nestjs-trpc) claims the request, and any other marked procedure in the same batch is refused with an `AuthConfigError` before its flow runs. The client sees `internal`. As a backstop, a second `setSession`, `signOut` or `clearSession` call in one request throws before writing.
  
  Behaviour change: a client that batched two cookie-writing mutations (for example with `httpBatchLink`) now gets an error for one of them. Send session-writing mutations one per request, with `httpLink` (through `splitLink`, as the docs show). Procedures without the marker share a batch as before.

### Patch Changes

- Updated dependencies [[`fb9f5d8`](https://github.com/noctcore/auth/commit/fb9f5d80dcdc515ff0e09b453c18136adddbd6ca), [`76717de`](https://github.com/noctcore/auth/commit/76717de578fbd4f83973dcf544acafeb1d5c9dad), [`5b79f16`](https://github.com/noctcore/auth/commit/5b79f16f9a597db92131f6684114c9f872cac4f5), [`c09f611`](https://github.com/noctcore/auth/commit/c09f611bc86253f33220e6d6ace54743de5cc1af), [`57440a0`](https://github.com/noctcore/auth/commit/57440a046b8f63cbca56f273ac611a8d6d391ebb), [`2ab09b7`](https://github.com/noctcore/auth/commit/2ab09b7b3769e14fbd72259138592df55a8bb3bb), [`e73f7a0`](https://github.com/noctcore/auth/commit/e73f7a0096808eb2fa9f705fe6c32983fb752e08)]:
  - @noctcore/auth@0.5.0

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
