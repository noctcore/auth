---
'@noctcore/auth': minor
'@noctcore/auth-prisma': minor
---

One-time codes and links no longer lose a race with a concurrent request.

- A submitted code that is expired, exhausted or at its last wrong guess is now removed by the hash that was read (`consume`), not by user and purpose. A code resent between the submit's read and its delete used to be removed with it and then answered `unknown`; it now stays valid.
- `OneTimeTokens.extendLink` no longer writes a link back with `put`. When the link was spent between the read and the write (two clicks on one revert link, one taking the lockout branch while the other spends it), the spent link used to be stored again with a far future expiry. It now stays spent.
- `TokenStore` has a new optional `extendExpiry(purpose, hash, expiresAt, now)`: it moves the expiry of the token with that hash only while it still exists and has not expired, in one step, and returns whether it changed one. `MemoryTokenStore` and `PrismaTokenStore` (a guarded `update`, no schema change) implement it. A store without it still works: `extendLink` then consumes the link and puts it back, which never revives a spent link but hides the link for one round trip.
- `tokenStoreConformance` has three new cases: a consume by the hash of a replaced token leaves the replacement, and `extendExpiry` extends a live token, creates nothing and never brings back a consumed one, also when racing the consume.

Behaviour change for store authors: `tokenStoreConformance` now expects `extendExpiry`, so a third-party `TokenStore` without it fails the two `extendExpiry` cases until it adds one. Implement it as an update guarded on `(purpose, hash)` that never inserts (no upsert). Nothing changes at runtime for such a store beyond the fallback above.
