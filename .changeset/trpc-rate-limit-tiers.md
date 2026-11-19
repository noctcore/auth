---
'@noctcore/auth-trpc': patch
---

`rateLimited` in the tRPC adapter can now count per signed-in user, take named tiers and skip exempt procedures. Counting per client IP stays the default.

- A rule with `keyBy: 'user'` counts a signed-in caller by user, across IPs. The user comes only from the session the core accepted; a call with no session or with a refused cookie counts by its client IP. The counter key holds a hash of the user id, never the id.
- `createAuthMiddlewares(t, { rateLimits })` takes named rules, checked at boot. `rateLimited(name, 'tier')` picks one (tier names are typed, an unknown one throws); without a rule, `rateLimited(name)` takes the tier named `name`, then the `default` tier, then 10 a minute as before.
- A procedure whose meta says `rateLimit: 'exempt'` is never counted, also by a limit on its base procedure. Add `RateLimitMeta` to your meta type. The nestjs-trpc `RateLimitMiddleware` reads the same meta and takes `keyBy`.
- New exported types: `AuthMiddlewareOptions`, `RateLimitKeyBy`, `RateLimitMeta`, `TrpcRateLimitRule`.
