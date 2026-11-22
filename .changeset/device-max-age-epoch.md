---
'@noctcore/auth': minor
'@noctcore/auth-redis': minor
---

`createAuth` refuses a device cookie or a trusted device that could outlive the session store's revocation epoch. The lockout device cookie is fenced by the user's epoch alone, and a store that forgets an epoch reads it as 0 again, so a cookie revoked by a sign-out everywhere used to verify once more after the epoch lapsed.

- `SessionStore` has a new optional `epochTtlMs`: how long the store keeps a user's epoch after its last write. Leave it out when the epoch never lapses (nothing changes for such a store).
- `RedisSessionStore` reports its `epochTtl` (90 days by default) as `epochTtlMs`.
- `createAuth` throws `AuthConfigError` when `throttle.lockout.deviceMaxAge` is longer than the store's `epochTtlMs`, and the two-factor plugin does the same for `trustedDevices.ttl`.
- `adoptLegacySessions` carries the wrapped store's `epochTtlMs` over, the plugin context's `sessions` exposes it, and the session store conformance suite checks that a bump keeps the epoch for the declared time.

Behaviour change: with the Redis store, an app whose `deviceMaxAge` or `trustedDevices.ttl` is longer than `epochTtl` no longer starts. The defaults (30 days against 90) are unaffected, but an `epochTtl` below 30 days now needs a `deviceMaxAge` (and a `trustedDevices.ttl`) no longer than it. Lower those, or raise `epochTtl`.
