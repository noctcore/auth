> **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

# @noctcore/auth-trpc

tRPC middlewares for [`@noctcore/auth`](https://github.com/noctcore/auth): a context that validates the session cookie through the core, guarded base procedures, CSRF on every mutation, error mapping that never reveals account state, and Zod schemas for the auth procedures. Plain tRPC on the fetch or Node adapters, and nestjs-trpc.

```ts
import { initTRPC } from '@trpc/server';
import { authErrorFormatter, createAuthContext, createAuthMiddlewares } from '@noctcore/auth-trpc';

export const authContext = createAuthContext({
  auth, // the createAuth(...) result
  trustedHops: 1, // reverse proxies in front of the server, 0 when none, or their addresses
  csrf: { secrets: [process.env.CSRF_SECRET], allowedOrigins: ['https://app.example'] },
  roles: (user) => [user.role],
});

type Context = Awaited<ReturnType<typeof authContext.node>>;

const t = initTRPC.context<Context>().create({ errorFormatter: authErrorFormatter });

export const { publicProcedure, protectedProcedure, freshAuth, role, rateLimited, writesCookies } =
  createAuthMiddlewares(t);
```

- **The context.** `authContext.fetch(opts, { remoteAddress })` or `authContext.node(opts)` validates the session cookie with the core once per request. `ctx.auth` holds the session, the request meta (client IP through the trusted hops, or an opt-in `clientIpHeader` such as `cf-connecting-ip`, which needs `trustedHops` as a proxy list naming the edge) and the cookie writers: `setSession(issued)` on sign-in and every rotation, `signOut()`, `clearSession(cookie)`, only in a procedure marked `writesCookies` (elsewhere they are not on the type and refuse at run time; on a streamed batch the marker refuses before the flow runs, and in a batch only one marked procedure runs: a second is refused before its flow). Each writes a CSRF cookie bound to the new session or pre-session. A streamed batch (`httpBatchStreamLink`) sends its headers before any procedure runs, and send mutations through `httpLink` with `splitLink`.
- **Guarded procedures.** `publicProcedure` checks CSRF on mutations; `protectedProcedure` also refuses a caller without a valid session and adds `ctx.user` (loaded from your store on the request) and `ctx.session`. `freshAuth(maxAge?)`, `role(...roles)` and `authed` run the session and CSRF checks themselves; `rateLimited(name, rule?)` counts per client IP with the core's throttle and refuses when the counter store is down.
- **CSRF on mutations.** The `Origin` must be allowed, `Sec-Fetch-Site` must say `same-origin` when sent, and the double-submit token must be bound to this session or pre-session. A refusal is `FORBIDDEN` with the message `forbidden` and nothing else.
- **Errors.** `toTRPCError(failure)` maps every `AuthErrorCode` to a tRPC code from the public code only; an unknown code becomes `internal`. `authErrorFormatter` never sends a stack, answers an input error with paths and issue codes (never the value), a body that does not parse and the codes `PARSE_ERROR`, `METHOD_NOT_SUPPORTED`, `UNSUPPORTED_MEDIA_TYPE`, `PAYLOAD_TOO_LARGE` and `NOT_FOUND` with a fixed message, and any internal error with `internal`. Messages your own procedures throw with any other code go out as written.
- **Schemas.** Zod inputs and outputs for every auth flow. Outputs strip every key they do not name, so a password hash added to your user record never reaches the client.
- **Checks for a test.** `assertProceduresGuarded(router)` fails on a procedure built with neither guarded builder, and on one marked public that asks for a session. `assertNoSecretQueries(router)` fails on a query whose input names a password, token, code or other secret anywhere in its Zod schema, since query inputs travel in the URL, and on an input it cannot read (`z.unknown()`, `z.custom()`, `z.preprocess()`, a validator that is not Zod 4).
- **nestjs-trpc.** `AuthGuardMiddleware` in `globalMiddlewares` closes every procedure whose meta does not say `auth: 'public'`; `WritesCookiesMiddleware`, `RoleMiddleware(...)`, `FreshAuthMiddleware(...)` and `RateLimitMiddleware(...)` run the same bodies as plain tRPC.

Needs `@trpc/server` 11.22.1 or later (within 11) and `zod` 4.3 or later (within 4).

The guide, with the context on each adapter, sign-in and rotation, and the checks to run in a test: [Use with tRPC](https://noctcore.github.io/auth/build/trpc/).
