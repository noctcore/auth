---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

Trust proxies by address, and read the client IP from an edge header through a trusted hop.

- `trustedHops` (in `clientIp` and in both adapters) also takes a list of proxy addresses, CIDR ranges and the Express presets `loopback`, `linklocal` and `uniquelocal`, which expand to the same ranges Express uses. With a list, `X-Forwarded-For` is read only when the socket address is inside it, and the first address outside it, from the right, is the client. `resolveTrustedProxies` checks and expands a list and refuses an unknown name, a malformed range or a range that holds every address (such as `0.0.0.0/0`); on the request path such a list trusts nothing instead of throwing. An IPv6 zone id on the socket address is dropped before matching. `isTrustedAddress`, `resolveTrustedHops`, `resolveClientIpHeader`, `TRUST_PROXY_PRESETS` and the `TrustedHops` type are exported too.
- New opt-in `clientIpHeader` option in the NestJS and tRPC adapters (and `trustedHeader` in `clientIp`), such as `cf-connecting-ip`. It needs `trustedHops` as a proxy list naming the edge (it is refused at boot with a hop count, which never checks the socket address), and the header wins only when the socket address is inside that list and the value is exactly one valid IP; otherwise the `X-Forwarded-For` rule decides. Off by default, so nothing changes until it is set.
- `trustedHopsFromEnv` and `configureTrustProxy` accept a `TRUST_PROXY` list such as `loopback, 10.0.0.0/8` and return it with the presets expanded (their return type is now `TrustedHops`, a number or a list); `configureTrustProxy` sets the same list on Express.
