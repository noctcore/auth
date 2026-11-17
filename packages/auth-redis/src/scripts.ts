/**
 * The Lua scripts behind every write that must be atomic. Each runs as one
 * Redis command, so no other client sees a half-done write.
 */
// KEYS[1] session, KEYS[2] user index, KEYS[3] epoch
// ARGV[1] json, ARGV[2] ttl ms, ARGV[3] expiresAt, ARGV[4] id, ARGV[5] now, ARGV[6] epoch ttl ms
export const CREATE = `
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[5])
local ttl = tonumber(ARGV[2])
if redis.call('PTTL', KEYS[2]) < ttl then redis.call('PEXPIRE', KEYS[2], ttl) end
local ettl = tonumber(ARGV[6])
if redis.call('EXISTS', KEYS[3]) == 1 and redis.call('PTTL', KEYS[3]) < ettl then redis.call('PEXPIRE', KEYS[3], ettl) end
return 1
`;

// KEYS[1] epoch; ARGV[1] epoch ttl ms
export const BUMP = `
local epoch = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return epoch
`;

// KEYS[1] counter; ARGV[1] window ms
export const INCREMENT = `
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if count == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}
`;

// KEYS[1] counter. DECR keeps the TTL; never below 0, never creates the key.
export const DECREMENT = `
local v = tonumber(redis.call('GET', KEYS[1]))
if v and v > 0 then redis.call('DECR', KEYS[1]) end
return 0
`;
