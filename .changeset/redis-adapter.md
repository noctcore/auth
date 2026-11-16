---
'@noctcore/auth-redis': minor
---

Add `RedisSessionStore`, `RedisCounterStore` and `redisStores`: sessions as JSON with a TTL at their absolute end, a per-user sorted-set index, `touch` as `SET XX KEEPTTL`, an epoch that outlives every session, and counters whose TTL is armed atomically by the first hit. Both pass the conformance suite on a real Redis.
