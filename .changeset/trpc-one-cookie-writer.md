---
'@noctcore/auth-trpc': minor
---

Only one procedure per HTTP request can write cookies. Every procedure of a tRPC batch shares `ctx.auth`, so two session-writing procedures in one batch (two sign-ins, or a sign-in and a rotation) used to both run: the browser kept the cookie written last, and the other session stayed valid with no browser holding it. Now the first procedure to reach `writesCookies` (or `WritesCookiesMiddleware` on nestjs-trpc) claims the request, and any other marked procedure in the same batch is refused with an `AuthConfigError` before its flow runs. The client sees `internal`. As a backstop, a second `setSession`, `signOut` or `clearSession` call in one request throws before writing.

Behaviour change: a client that batched two cookie-writing mutations (for example with `httpBatchLink`) now gets an error for one of them. Send session-writing mutations one per request, with `httpLink` (through `splitLink`, as the docs show). Procedures without the marker share a batch as before.
