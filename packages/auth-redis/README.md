> **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

# @noctcore/auth-redis

Redis session, counter and two-factor stores for [`@noctcore/auth`](https://github.com/noctcore/auth).

```ts
import { Redis } from 'ioredis';
import { redisStores } from '@noctcore/auth-redis';

const { sessions, counters } = redisStores(new Redis(process.env.REDIS_URL), { prefix: 'auth:' });
```

- Needs Redis 6.2 or newer. Redis Cluster is not supported (a session and its user's index are written by one script); a single primary with replicas or Sentinel is.
- Sessions are JSON under `s:<id>` with a TTL at their absolute end, indexed per user in a sorted set; `touch` is `SET XX KEEPTTL`, so it never brings back a revoked session.
- The revocation epoch outlives every session (`epochTtl`, default 90 days). Set `maxSessionTtl` (default 30 days) to at least the core's remember-me TTL (`session.rememberMeTtl`, also 30 days by default). The store refuses to start unless `epochTtl` is longer, `createAuth` refuses a remember-me or absolute TTL longer than `maxSessionTtl`, and `create` refuses a session that would outlive its epoch. If an epoch ever lapses anyway, the user's sessions fail closed.
- Counters arm their TTL atomically on the first hit; every key the session and counter stores write expires.

## Two-factor store

`RedisTwoFactorStore` backs the two-factor plugin (`@noctcore/auth/two-factor`):

```ts
import { RedisTwoFactorStore } from '@noctcore/auth-redis';

const store = new RedisTwoFactorStore(redis, { prefix: 'auth:' });
```

- Every compare-and-set (the last accepted TOTP step, confirming an enrollment, spending a recovery code) is one Lua script or one atomic command.
- Trusted devices and step-up proofs expire with their TTL. The factor and the recovery codes have no TTL: they are account data. Keep them only on a Redis with persistence (AOF), or put them in Postgres with `PrismaTwoFactorStore` from `@noctcore/auth-prisma`.

## Run Redis with `noeviction`

Set `maxmemory-policy noeviction` on the Redis that holds these keys (and give it enough memory). Under an evicting policy Redis may drop a revocation epoch or a lockout counter to make room: a dropped epoch signs users out, and a dropped counter quietly hands an attacker a fresh budget. With `noeviction`, a full Redis refuses writes instead, and the auth flows fail closed.

```
maxmemory-policy noeviction
```

All three stores pass the conformance suite from `@noctcore/auth/testing` on a real Redis in CI.
