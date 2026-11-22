---
'@noctcore/auth': minor
'@noctcore/auth-redis': minor
---

`createAuth` refuses a device cookie or a trusted device that could outlive the session store's revocation epoch. The lockout device cookie is fenced by the user's epoch alone, and a store that forgets an epoch reads it as 0 again, so a cookie revoked by a sign-out everywhere used to verify once more after the epoch lapsed.

- `SessionStore` has a new optional `epochTtlMs`: how long the store keeps a user's epoch after its last write. Leave it out when the epoch never lapses (nothing changes for such a store).
- `RedisSessionStore` reports its `epochTtl` (90 days by default) as `epochTtlMs`.
- `createAuth` throws `AuthConfigError` unless `throttle.lockout.deviceMaxAge` is at least a minute shorter than the store's `epochTtlMs`, and the two-factor plugin does the same for `trustedDevices.ttl`. The minute is the clock skew a device cookie is allowed (`DEVICE_CLOCK_SKEW_MS`): its issue time comes from the server that set it, so equal values are refused too.
- `createAuth` refuses a session store whose declared `epochTtlMs` or `maxSessionTtlMs` is not a positive number (NaN, zero, negative or not a number), instead of skipping the check.
- `adoptLegacySessions` carries the wrapped store's `epochTtlMs` over, the plugin context's `sessions` exposes it, and the session store conformance suite checks that a bump keeps the epoch for the declared time.

Behaviour change: with the Redis store, an app whose `deviceMaxAge` or `trustedDevices.ttl` is not at least a minute shorter than `epochTtl` no longer starts. The defaults (30 days against 90) are unaffected, but an `epochTtl` below 30 days now needs a `deviceMaxAge` (and a `trustedDevices.ttl`) at least a minute shorter. Lower those, or raise `epochTtl`.
