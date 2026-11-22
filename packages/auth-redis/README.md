> **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

# @noctcore/auth-redis

Redis session, counter, two-factor and membership stores for [`@noctcore/auth`](https://github.com/noctcore/auth).

```ts
import { Redis } from 'ioredis';
import { redisStores } from '@noctcore/auth-redis';

const { sessions, counters } = redisStores(new Redis(process.env.REDIS_URL), { prefix: 'auth:' });
```

- Needs Redis 6.2 or newer. Redis Cluster is not supported (a session and its user's index are written by one script); a single primary with replicas or Sentinel is.
- Sessions are JSON under `s:<id>` with a TTL at their absolute end, indexed per user in a sorted set; `touch` is `SET XX KEEPTTL`, so it never brings back a revoked session.
- The revocation epoch outlives every session (`epochTtl`, default 90 days). Set `maxSessionTtl` (default 30 days) to at least the core's remember-me TTL (`session.rememberMeTtl`, also 30 days by default). The store refuses to start unless `epochTtl` is longer, `createAuth` refuses a remember-me or absolute TTL longer than `maxSessionTtl`, and `create` refuses a session that would outlive its epoch. If an epoch ever lapses anyway, the user's sessions fail closed. Device cookies (`throttle.lockout.deviceMaxAge`, 30 days by default) and two-factor trusted devices (`trustedDevices.ttl`) are fenced by the epoch alone, so `createAuth` refuses either one when it is longer than `epochTtl`.
- Counters arm their TTL atomically on the first hit; every key the session and counter stores write expires.

## Two-factor store

`RedisTwoFactorStore` backs the two-factor plugin (`@noctcore/auth/two-factor`):

```ts
import { RedisTwoFactorStore } from '@noctcore/auth-redis';

const store = new RedisTwoFactorStore(redis, { prefix: 'auth:' });
```

- Every compare-and-set (the last accepted TOTP step, confirming an enrollment, spending a recovery code) is one Lua script or one atomic command.
- Trusted devices and step-up proofs expire with their TTL. The factor and the recovery codes have no TTL: they are account data. Keep them only on a Redis with persistence (AOF), or put them in Postgres with `PrismaTwoFactorStore` from `@noctcore/auth-prisma`.

## Membership store

`RedisMembershipStore` backs the membership plugin (`@noctcore/auth/membership`):

```ts
import { RedisMembershipStore } from '@noctcore/auth-redis';

const store = new RedisMembershipStore(redis, { prefix: 'auth:' });
```

- A scope's members are one hash under `ms:<scope>`. A role change or a removal is one Lua script that checks the member's role and the other admins and writes, so two admins demoting each other at once leave one admin.
- Members have no TTL: they are account data. Keep them only on a Redis with persistence (AOF), or put them in Postgres with `PrismaMembershipStore`.

## Invitation store

`RedisInvitationStore` backs the invitations plugin (`@noctcore/auth/invitations`):

```ts
import { RedisInvitationStore } from '@noctcore/auth-redis';

const store = new RedisInvitationStore(redis, { prefix: 'auth:' });
```

- Each invitation is JSON under `inv:h:<hash>`, with indexes under `inv:p:` (one per scope and address, named by a SHA-256 digest, so no address is a key name), `inv:s:<scope>` and `inv:u:<inviterId>`. Every key has a TTL at the invitation's expiry.
- Creating and consuming are each one Lua script, so of many concurrent accepts exactly one gets the invitation.

## Run Redis with `noeviction`

Set `maxmemory-policy noeviction` on the Redis that holds these keys (and give it enough memory). Under an evicting policy Redis may drop a revocation epoch, a lockout counter or a lock key to make room: a dropped epoch signs users out, a dropped counter quietly hands an attacker a fresh budget, and a dropped lock key ends a lock early. With `noeviction`, a full Redis refuses writes instead, and the auth flows fail closed.

```
maxmemory-policy noeviction
```

All three stores pass the conformance suite from `@noctcore/auth/testing` on a real Redis in CI.
