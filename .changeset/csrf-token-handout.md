---
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

Both adapters now hand the CSRF token to a client that cannot read the API's cookies, such as a desktop shell on its own scheme or a web app on another origin than the API. Until now such a client had no token for its first sign-in, nor for any unsafe request after a restart with a persistent session.

- NestJS: `SessionCookies.csrfToken(request, response)` returns `{ csrfToken }` for a `@Public()` GET route (for example `GET /csrf-token`). It is exactly the token `CsrfMiddleware` set or kept as the `csrf` cookie on that response, minting the pre-session and the cookie when missing, and it marks the response `Cache-Control: no-store`. It throws an `AuthConfigError` on an exempt path (which still mints nothing) and on an unsafe method.
- tRPC: `ctx.auth.csrfToken()` returns `{ csrfToken }` in a public query sent with GET, with the same guarantees. It throws an `AuthConfigError` on a request with an unsafe method, on a streamed batch (`httpBatchStreamLink`) and in a subscription.
- tRPC: `authResponseMeta(responseMeta)` wraps the app's `responseMeta` (or stands alone as `authResponseMeta()`) and keeps `Cache-Control: no-store` on every response that handed out a token, dropping every `Cache-Control`, `Surrogate-Control`, `CDN-Cache-Control` and `*-CDN-Cache-Control` header the app returned. Without it, tRPC lets the headers `responseMeta` returns replace or join the `no-store` the call set, so a caching rule there (such as `s-maxage` on public queries, or a CDN cache header) could put the token in a shared cache. Pass it to every tRPC handler you create that serves the token query; nestjs-trpc passes no `responseMeta`, so there is nothing to wrap there.
- NestJS: `no-store` does not reach a cache inside the app. Keep the token route out of `CacheInterceptor`, any other response cache, and any interceptor or middleware that sets `Cache-Control` after the handler.
- The token stays bound to the session or pre-session and the cookie is still required next to it, and an unsafe request from an origin outside the allowlist is refused on its `Origin` and `Sec-Fetch-Site` whatever the token, and whatever the app's CORS lets a page read, so reading it from a response grants nothing a cross-site page could use. Attack tests A100 and A101 pin that.
