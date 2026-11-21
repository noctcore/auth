---
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

Both adapters now hand the CSRF token to a client that cannot read the API's cookies, such as a desktop shell on its own scheme or a web app on another origin than the API. Until now such a client had no token for its first sign-in, nor for any unsafe request after a restart with a persistent session.

- NestJS: `SessionCookies.csrfToken(request, response)` returns `{ csrfToken }` for a `@Public()` GET route (for example `GET /csrf-token`). It is exactly the token `CsrfMiddleware` set or kept as the `csrf` cookie on that response, minting the pre-session and the cookie when missing, and it marks the response `Cache-Control: no-store`. It throws an `AuthConfigError` on an exempt path (which still mints nothing) and on an unsafe method.
- tRPC: `ctx.auth.csrfToken()` returns `{ csrfToken }` in a public query sent with GET, with the same guarantees. It throws an `AuthConfigError` on a request with an unsafe method and on a streamed batch (`httpBatchStreamLink`).
- The token stays bound to the session or pre-session and the cookie is still required next to it, so reading it from a response grants nothing a cross-site page could use. Attack tests A100 and A101 pin that.
