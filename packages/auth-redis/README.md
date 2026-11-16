# @noctcore/auth-redis

Redis session and counter stores for [`@noctcore/auth`](https://github.com/noctcore/auth).

```ts
import { Redis } from 'ioredis';
import { redisStores } from '@noctcore/auth-redis';

const { sessions, counters } = redisStores(new Redis(process.env.REDIS_URL), { prefix: 'auth:' });
```

- Needs Redis 6.2 or newer. Redis Cluster is not supported (a session and its user's index are written by one script); a single primary with replicas or Sentinel is.
- Sessions are JSON under `s:<id>` with a TTL at their absolute end, indexed per user in a sorted set; `touch` is `SET XX KEEPTTL`, so it never brings back a revoked session.
- The revocation epoch outlives every session (`epochTtl`, default 90 days). If it ever lapses, the user's sessions fail closed.
- Counters arm their TTL atomically on the first hit; every key the stores write expires.

Both stores pass the conformance suite from `@noctcore/auth/testing` on a real Redis in CI.
