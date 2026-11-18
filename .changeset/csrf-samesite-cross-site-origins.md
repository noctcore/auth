---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

The NestJS and tRPC adapters now work with a desktop shell served from its own scheme (such as `app://desktop`).

- The CSRF cookie (`__Host-csrf`), the pre-session cookie (`__Host-presession`) and the blank cookie that clears a refused session take the session cookie's `SameSite` for the request's `Origin`, instead of a fixed `Lax`. A cookie written next to a new session takes that session cookie's own value. With the default `session.cookie.sameSite` (`'lax'`) nothing changes. An app that sets it to `'strict'`, `'none'` or a function now gets the same answer on these cookies too.
- New `csrf.crossSiteOrigins` option in both adapters: exact origins whose cross-site requests are accepted. A listed origin passes the `Origin` check, and its `Sec-Fetch-Site: cross-site` requests pass the fetch-metadata check. The double-submit token is still required. Matching is exact (scheme, host and port). At boot, an entry fails if it is a wildcard, `null`, has no host, or carries a path, query, fragment or user info. The list is empty by default, so behaviour is unchanged until you name an origin. Trust a listed origin as much as your own: see the threat model.
- Core: `resolveSameSite(config, origin)` gives the session cookie's `SameSite` for an origin (used by every cookie that travels with it), `verifyFetchSite` takes optional `origin` and `crossSiteOrigins` inputs, and `assertExactOrigins(origins, option)` checks an origin allowlist at boot. Each adapter also refuses `SameSite=None` when its cookies are not Secure, even if the cookie config claims they are.
