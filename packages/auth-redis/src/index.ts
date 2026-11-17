/**
 * @noctcore/auth-redis: Redis session and counter stores for @noctcore/auth.
 *
 * Layout (every key under `prefix`, default `auth:`):
 *
 * - `s:<sessionId>`  the session as JSON, with a TTL at its absolute end;
 * - `u:<userId>`     a sorted set of the user's session ids, scored by expiry;
 * - `e:<userId>`     the user's revocation epoch, kept alive past every session;
 * - `c:<key>`        a fixed-window counter, its TTL armed by the first hit;
 * - `tf:*`           the two-factor plugin's store (`RedisTwoFactorStore`), see its file;
 * - `ms:*`           the membership plugin's store (`RedisMembershipStore`), see its file;
 * - `inv:*`          the invitations plugin's store (`RedisInvitationStore`), see its file.
 *
 * Requires Redis 6.2 or newer (`SET ... XX KEEPTTL`). Multi-key scripts touch a
 * session and its user's index together, so Redis Cluster is not supported;
 * a single primary, with replicas or Sentinel, is.
 */
import type { Redis } from 'ioredis';
import { RedisCounterStore } from './counter-store';
import type { RedisSessionStoreOptions } from './options';
import { RedisSessionStore } from './session-store';

export { RedisCounterStore } from './counter-store';
export { RedisInvitationStore } from './invitation-store';
export { RedisMembershipStore } from './membership-store';
export type { RedisSessionStoreOptions, RedisStoreOptions } from './options';
export { RedisSessionStore } from './session-store';
export { RedisTwoFactorStore } from './two-factor-store';

/** Both Redis stores on one client. */
export function redisStores(redis: Redis, options: RedisSessionStoreOptions = {}) {
  return {
    sessions: new RedisSessionStore(redis, options),
    counters: new RedisCounterStore(redis, options),
  };
}
