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

// Two-factor store. A factor is a hash: secret, confirmed (0 or 1), lastStep, createdAt.

// KEYS[1] factor; ARGV[1] secret, ARGV[2] createdAt. Never over a confirmed factor.
export const PUT_PENDING_FACTOR = `
if redis.call('HGET', KEYS[1], 'confirmed') == '1' then return 0 end
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'secret', ARGV[1], 'confirmed', '0', 'lastStep', '-1', 'createdAt', ARGV[2])
return 1
`;

// KEYS[1] factor; ARGV[1] secret, ARGV[2] step. Only the pending factor that still holds this secret.
export const CONFIRM_FACTOR = `
local f = redis.call('HMGET', KEYS[1], 'confirmed', 'secret')
if f[1] ~= '0' or f[2] ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'confirmed', '1', 'lastStep', ARGV[2])
return 1
`;

// KEYS[1] factor; ARGV[1] step. Only forward, only on a confirmed factor.
export const ADVANCE_STEP = `
local f = redis.call('HMGET', KEYS[1], 'confirmed', 'lastStep')
if f[1] ~= '1' or tonumber(f[2]) >= tonumber(ARGV[1]) then return 0 end
redis.call('HSET', KEYS[1], 'lastStep', ARGV[1])
return 1
`;

// KEYS[1] codes set; ARGV the new hashes (none deletes the set).
export const REPLACE_RECOVERY_CODES = `
redis.call('DEL', KEYS[1])
if #ARGV > 0 then redis.call('SADD', KEYS[1], unpack(ARGV)) end
return 1
`;

// KEYS[1] device, KEYS[2] user's device index; ARGV[1] json, ARGV[2] ttl ms, ARGV[3] createdAt,
// ARGV[4] hash, ARGV[5] maxPerUser, ARGV[6] device key prefix.
// Stores the device, then deletes the oldest beyond maxPerUser and any whose key has expired.
export const ADD_TRUSTED_DEVICE = `
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[4])
local members = redis.call('ZRANGE', KEYS[2], 0, -1)
local live = {}
for _, hash in ipairs(members) do
  if redis.call('EXISTS', ARGV[6] .. hash) == 1 then table.insert(live, hash)
  else redis.call('ZREM', KEYS[2], hash) end
end
local extra = #live - tonumber(ARGV[5])
for i = 1, extra do
  redis.call('DEL', ARGV[6] .. live[i])
  redis.call('ZREM', KEYS[2], live[i])
end
local ttl = tonumber(ARGV[2])
if redis.call('PTTL', KEYS[2]) < ttl then redis.call('PEXPIRE', KEYS[2], ttl) end
return 1
`;

// KEYS[1] user's device index; ARGV[1] device key prefix.
export const DELETE_TRUSTED_DEVICES = `
local members = redis.call('ZRANGE', KEYS[1], 0, -1)
for _, hash in ipairs(members) do redis.call('DEL', ARGV[1] .. hash) end
redis.call('DEL', KEYS[1])
return #members
`;

// Membership store. A scope is a hash: userId -> role. No TTL: account data.

// KEYS[1] scope; ARGV[1] userId, ARGV[2] from, ARGV[3] '1' to remove or '0' to
// change, ARGV[4] the new role, ARGV[5..] the admin roles. The check of the
// other admins and the write are one script, so no other write lands between.
export const GUARDED_MEMBER_WRITE = `
local role = redis.call('HGET', KEYS[1], ARGV[1])
if not role then return 'missing' end
if role ~= ARGV[2] then return 'stale' end
local admins = {}
for i = 5, #ARGV do admins[ARGV[i]] = true end
local remove = ARGV[3] == '1'
if admins[role] and (remove or not admins[ARGV[4]]) then
  local all = redis.call('HGETALL', KEYS[1])
  local others = false
  for i = 1, #all, 2 do
    if all[i] ~= ARGV[1] and admins[all[i + 1]] then others = true break end
  end
  if not others then return 'last_admin' end
end
if remove then redis.call('HDEL', KEYS[1], ARGV[1]) else redis.call('HSET', KEYS[1], ARGV[1], ARGV[4]) end
return 'done'
`;

// The invitation store. Each row is JSON at <prefix>h:<hash> and names its own
// index keys (pair, scope set, inviter set), so every script can clean up
// after it without recomputing a key.
//
// KEYS[1] pair, KEYS[2] row, KEYS[3] scope set, KEYS[4] inviter set;
// ARGV[1] hash, ARGV[2] row JSON, ARGV[3] ttl ms, ARGV[4] now ms, ARGV[5] row key prefix.
// 0 while a live invitation holds the pair; an expired one is replaced.
export const CREATE_INVITATION = `
local old = redis.call('GET', KEYS[1])
if old then
  local row = redis.call('GET', ARGV[5] .. old)
  if row then
    if tonumber(cjson.decode(row).expiresAt) > tonumber(ARGV[4]) then return 0 end
    redis.call('DEL', ARGV[5] .. old)
  end
  redis.call('SREM', KEYS[3], old)
end
local ttl = tonumber(ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'PX', ttl)
redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl)
for i = 3, 4 do
  redis.call('SADD', KEYS[i], ARGV[1])
  if redis.call('PTTL', KEYS[i]) < ttl then redis.call('PEXPIRE', KEYS[i], ttl) end
end
return 1
`;

// Deletes one row and its index entries. Shared by the scripts below.
const DROP_INVITATION = `
local function drop(key, row)
  local data = cjson.decode(row)
  redis.call('DEL', key)
  if redis.call('GET', data.pair) == data.hash then redis.call('DEL', data.pair) end
  redis.call('SREM', data.scopeSet, data.hash)
  redis.call('SREM', data.inviterSet, data.hash)
end
`;

// KEYS[1] row. The row's JSON, removed in the same step, or false.
export const CONSUME_INVITATION = `${DROP_INVITATION}
local row = redis.call('GET', KEYS[1])
if not row then return false end
drop(KEYS[1], row)
return row
`;

// KEYS[1] scope set; ARGV[1] id, ARGV[2] row key prefix. 1 when a row went.
export const REVOKE_INVITATION = `${DROP_INVITATION}
for _, hash in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local key = ARGV[2] .. hash
  local row = redis.call('GET', key)
  if not row then
    redis.call('SREM', KEYS[1], hash)
  elseif cjson.decode(row).id == ARGV[1] then
    drop(key, row)
    return 1
  end
end
return 0
`;

// KEYS[1] inviter set; ARGV[1] row key prefix.
export const DELETE_INVITER_INVITATIONS = `${DROP_INVITATION}
for _, hash in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local key = ARGV[1] .. hash
  local row = redis.call('GET', key)
  if row then drop(key, row) end
end
redis.call('DEL', KEYS[1])
return 1
`;
