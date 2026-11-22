> **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

# @noctcore/auth-redis

Redis session, counter, two-factor and membership stores for [`@noctcore/auth`](https://github.com/noctcore/auth).

```ts
import { Redis } from 'ioredis';
import { redisStores } from '@noctcore/auth-redis';

const redis = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
  connectTimeout: 2_000,
  commandTimeout: 1_000,
  retryStrategy: (attempt) => Math.min(attempt * 200, 2_000),
});

redis.on('error', (error) => console.error('redis', error.name)); // log it, or ioredis prints every failure

// With the offline queue off, a command sent before the connection is up is
// rejected, so wait for it (bounded) before serving.
await new Promise<void>((resolve, reject) => {
  const timer = setTimeout(
    () => reject(new Error('Redis was not ready within 10 seconds')),
    10_000,
  );

  redis.once('ready', () => {
    clearTimeout(timer);
    resolve();
  });
});

const { sessions, counters } = redisStores(redis, { prefix: 'auth:' });
```

- Needs Redis 6.2 or newer. Redis Cluster is not supported (a session and its user's index are written by one script); a single primary with replicas or Sentinel is.
- Sessions are JSON under `s:<id>` with a TTL at their absolute end, indexed per user in a sorted set; `touch` is `SET XX KEEPTTL`, so it never brings back a revoked session.
- The revocation epoch outlives every session (`epochTtl`, default 90 days). Set `maxSessionTtl` (default 30 days) to at least the core's remember-me TTL (`session.rememberMeTtl`, also 30 days by default). The store refuses to start unless `epochTtl` is longer, `createAuth` refuses a remember-me or absolute TTL longer than `maxSessionTtl`, and `create` refuses a session that would outlive its epoch. If an epoch ever lapses anyway, the user's sessions fail closed. Device cookies (`throttle.lockout.deviceMaxAge`, 30 days by default) and two-factor trusted devices (`trustedDevices.ttl`) are fenced by the epoch alone, so `createAuth` refuses either one unless it is at least a minute (the clock skew a device cookie is allowed) shorter than `epochTtl`.
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

## Bound the client so an outage fails fast

Create the ioredis client with the options above; ioredis's defaults are not safe for a request path. With them, a Redis that stops answering holds every request (session check, sign-in, rate limit) for about 73 seconds (20 retries per command with backoff) before the call rejects, and under load the waiting requests pile up until the app is down too. In ioredis 6, measured against a port with nothing listening: the defaults reject after about 73 s, the options above after a few milliseconds.

- `maxRetriesPerRequest: 1` ends a command after one reconnect attempt (`MaxRetriesPerRequestError`) instead of 20.
- `enableOfflineQueue: false` rejects a command at once while the client is not connected, instead of queueing it until the connection returns. Commands sent before the first connection is ready are rejected too, so wait for the client's `ready` event before you start serving.
- `connectTimeout` and `commandTimeout` (milliseconds) bound a connection attempt and a command that gets no reply, for the case where the network drops packets instead of refusing them (`Command timed out`). Size `commandTimeout` above your Redis p99, including a loaded instance and the longest script the stores run, or healthy calls fail. A command that timed out may still have run on the server; the library fails closed on the rejection, so that is safe.
- `retryStrategy` sets how long the client waits before it reconnects in the background; it does not delay a request. The client reconnects on its own when Redis comes back, with no restart, because this strategy never returns `null`. Do not return `null` from it: that ends reconnection for good, and every later command fails until the process restarts. The default backs off to 5 seconds.

What the app sees: the store call rejects with the ioredis error, and the core does not catch it. A flow such as `validateRequest`, sign-in or a rate-limit hit rejects instead of returning a refusal, so no request is let through on a failed check (it fails closed). `@noctcore/auth-nestjs` turns the rejection into a 500 and `@noctcore/auth-trpc` into an internal error, both logging only the error's name. In your own handler, catch the rejection, answer 503 and log `error.name` (a store error can carry a key name).
