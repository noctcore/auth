---
'@noctcore/auth': minor
'@noctcore/auth-prisma': minor
---

A one-time code check now counts its attempt on the code it read, and a link extend never revives a link that expired meanwhile.

- `TokenStore` has a new optional `incrementAttemptsByHash(purpose, hash, max)`: the capped attempt increment of `incrementAttempts`, on the token with that hash only, null when that token is gone or at the cap. `MemoryTokenStore` and `PrismaTokenStore` (a guarded `update`, no schema change) implement it. A code resent between a check's read and its count used to be charged for the guess at the old code, and the old code answered as if it had been compared; the resent code now keeps every attempt. A store without it still works and counts by user and purpose, as before.
- `extendExpiry` now takes the time as a fourth argument and refuses a token whose expiry is not after it, in the same update. `MemoryTokenStore` and `PrismaTokenStore` implement it. The consume and put fallback of `extendLink` (for a store without `extendExpiry`) no longer puts back a link that expired between its check and the put.
- The fallback's two remaining gaps are documented on `TokenStore` and in the store adapter guide: its put replaces a link of the same user and purpose issued in between, and a put that fails after the consume loses the link.
- `tokenStoreConformance` has three new cases: `extendExpiry` never extends an expired token, and `incrementAttemptsByHash` counts only the token with that hash and never passes the cap under concurrent callers.

**Behaviour change:** a code check whose code was replaced by a resend, or spent by a concurrent winner, before its attempt was counted now answers `consumed` (a guess at a code that no longer exists is never compared), where it answered `mismatch`, `exhausted` or, through the old count, charged the new code. The flows report it with the `consumed` reason (`reset_code_consumed`, `verification_consumed`, `email_change_consumed`), all still `invalid_token`. For store authors: `tokenStoreConformance` now expects `incrementAttemptsByHash` and the `now` argument of `extendExpiry`, so a third-party `TokenStore` fails the new cases until it adds them. Implement both as updates guarded on `(purpose, hash)` (and on `expiresAt` after `now` for the extend) that never insert.
