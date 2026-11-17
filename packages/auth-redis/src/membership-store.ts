/**
 * The membership plugin's store on Redis.
 *
 * - `ms:<scope>`  the scope's members, a hash of user id to role.
 *
 * A role change or a removal is one Lua script that checks the member's role
 * and the other admins of the scope and writes, so it is atomic: two admins
 * demoting each other at the same moment cannot both succeed. Members have no
 * TTL: they are account data, so run Redis with persistence (AOF) if it holds
 * them, or keep them in Postgres (`@noctcore/auth-prisma`).
 */
import type { MembershipStore, MemberWrite, StoredMember } from '@noctcore/auth';
import type { Redis } from 'ioredis';
import type { RedisStoreOptions } from './options';
import { GUARDED_MEMBER_WRITE } from './scripts';

const WRITES: ReadonlySet<string> = new Set(['done', 'missing', 'stale', 'last_admin']);

/** The `MembershipStore` on Redis. */
export class RedisMembershipStore implements MembershipStore {
  private readonly prefix: string;

  constructor(
    private readonly redis: Redis,
    options: Pick<RedisStoreOptions, 'prefix'> = {},
  ) {
    this.prefix = `${options.prefix ?? 'auth:'}ms:`;
  }

  private key(scope: string): string {
    return `${this.prefix}${scope}`;
  }

  async findMember(scope: string, userId: string): Promise<StoredMember | null> {
    const role = await this.redis.hget(this.key(scope), userId);

    return role === null ? null : { scope, userId, role };
  }

  async listMembers(scope: string): Promise<StoredMember[]> {
    const members = await this.redis.hgetall(this.key(scope));

    return Object.entries(members).map(([userId, role]) => ({ scope, userId, role }));
  }

  async addMember(member: StoredMember): Promise<boolean> {
    return (await this.redis.hsetnx(this.key(member.scope), member.userId, member.role)) === 1;
  }

  changeRole(input: {
    readonly scope: string;
    readonly userId: string;
    readonly from: string;
    readonly to: string;
    readonly adminRoles: readonly string[];
  }): Promise<MemberWrite> {
    return this.write(input, '0', input.to);
  }

  removeMember(input: {
    readonly scope: string;
    readonly userId: string;
    readonly from: string;
    readonly adminRoles: readonly string[];
  }): Promise<MemberWrite> {
    return this.write(input, '1', '');
  }

  private async write(
    input: {
      readonly scope: string;
      readonly userId: string;
      readonly from: string;
      readonly adminRoles: readonly string[];
    },
    remove: '0' | '1',
    to: string,
  ): Promise<MemberWrite> {
    const result = await this.redis.eval(
      GUARDED_MEMBER_WRITE,
      1,
      this.key(input.scope),
      input.userId,
      input.from,
      remove,
      to,
      ...input.adminRoles,
    );

    if (typeof result !== 'string' || !WRITES.has(result))
      throw new Error('Unexpected reply from the membership script');

    return result as MemberWrite;
  }
}
