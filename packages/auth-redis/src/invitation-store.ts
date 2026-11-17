/**
 * The invitations plugin's store on Redis.
 *
 * - `inv:h:<hash>`  the invitation as JSON, expiring with it.
 * - `inv:p:<digest>`  the hash of the live invitation for one scope and
 *   address; the digest is SHA-256 of both, so no raw address is a key name.
 * - `inv:s:<scope>` and `inv:u:<inviterId>`  sets of hashes, to list a scope
 *   and to delete an inviter's invitations; they expire with their newest entry.
 *
 * Every TTL is the invitation's remaining lifetime, so Redis drops expired
 * invitations itself. `create` and `consume` are each one Lua script: of many
 * concurrent consumers exactly one gets the row, and of many concurrent creates
 * for one scope and address at most one writes.
 */
import { createHash } from 'node:crypto';
import type { InvitationStore, StoredInvitation } from '@noctcore/auth';
import type { Redis } from 'ioredis';
import type { RedisStoreOptions } from './options';
import {
  CONSUME_INVITATION,
  CREATE_INVITATION,
  DELETE_INVITER_INVITATIONS,
  REVOKE_INVITATION,
} from './scripts';

/** A stored row: the invitation plus the names of its index keys. */
interface Row extends StoredInvitation {
  readonly pair: string;
  readonly scopeSet: string;
  readonly inviterSet: string;
}

/** The `InvitationStore` on Redis. */
export class RedisInvitationStore implements InvitationStore {
  private readonly prefix: string;

  constructor(
    private readonly redis: Redis,
    options: Pick<RedisStoreOptions, 'prefix'> = {},
  ) {
    this.prefix = `${options.prefix ?? 'auth:'}inv:`;
  }

  private rowKey(hash: string): string {
    return `${this.prefix}h:${hash}`;
  }

  private scopeKey(scope: string): string {
    return `${this.prefix}s:${scope}`;
  }

  async create(invitation: StoredInvitation, now: number): Promise<boolean> {
    const digest = createHash('sha256')
      .update(`${invitation.scope}\n${invitation.email}`)
      .digest('hex');

    const row: Row = {
      ...invitation,
      pair: `${this.prefix}p:${digest}`,
      scopeSet: this.scopeKey(invitation.scope),
      inviterSet: `${this.prefix}u:${invitation.inviterId}`,
    };

    const created = await this.redis.eval(
      CREATE_INVITATION,
      4,
      row.pair,
      this.rowKey(invitation.hash),
      row.scopeSet,
      row.inviterSet,
      invitation.hash,
      JSON.stringify(row),
      String(Math.max(1, invitation.expiresAt - now)),
      String(now),
      `${this.prefix}h:`,
    );

    return created === 1;
  }

  async findByHash(hash: string): Promise<StoredInvitation | null> {
    return parse(await this.redis.get(this.rowKey(hash)));
  }

  async consume(hash: string): Promise<StoredInvitation | null> {
    return parse(
      (await this.redis.eval(CONSUME_INVITATION, 1, this.rowKey(hash))) as string | null,
    );
  }

  async listByScope(scope: string, now: number): Promise<StoredInvitation[]> {
    const hashes = await this.redis.smembers(this.scopeKey(scope));

    if (hashes.length === 0) return [];

    const rows = await this.redis.mget(...hashes.map((hash) => this.rowKey(hash)));

    return rows
      .map(parse)
      .filter((i): i is StoredInvitation => i !== null && i.scope === scope && i.expiresAt > now);
  }

  async revoke(scope: string, id: string): Promise<boolean> {
    const result = await this.redis.eval(
      REVOKE_INVITATION,
      1,
      this.scopeKey(scope),
      id,
      `${this.prefix}h:`,
    );

    return result === 1;
  }

  async deleteByInviter(inviterId: string, scope?: string): Promise<void> {
    await this.redis.eval(
      DELETE_INVITER_INVITATIONS,
      1,
      `${this.prefix}u:${inviterId}`,
      `${this.prefix}h:`,
      ...(scope === undefined ? [] : [scope]),
    );
  }
}

/** The invitation in a stored row, without the index key names. */
function parse(json: string | null): StoredInvitation | null {
  if (json === null) return null;

  const row = JSON.parse(json) as Row;

  return {
    id: row.id,
    hash: row.hash,
    scope: row.scope,
    email: row.email,
    inviterId: row.inviterId,
    payload: row.payload,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
  };
}
