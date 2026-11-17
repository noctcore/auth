/**
 * The membership plugin's store on the `AuthMember` and `AuthMemberScope`
 * tables from `prisma/auth.prisma`.
 *
 * A guarded write (a role change or a removal) reads the scope's version, the
 * member and the count of the other admins, then commits two statements in one
 * transaction: an update of the scope row guarded on the version it read, and
 * the member write itself. If any membership write of the scope committed in
 * between, the version no longer matches, the transaction rolls back, and the
 * decision is made again on fresh rows. In PostgreSQL the guarded update also
 * waits for a concurrent one on the same scope row and re-checks its `where`
 * after that one commits, so two demotions of the last two admins cannot both
 * commit at any isolation level.
 */
import type { MembershipStore, MemberWrite, StoredMember } from '@noctcore/auth';
import type { PrismaMembershipDelegates } from './delegates';
import { P2002, P2025, prismaCode } from './prisma-errors';

interface MemberRow {
  scope: string;
  userId: string;
  role: string;
}

/** Retries before a write that keeps losing the race to other writes of its scope gives up. */
const MAX_ATTEMPTS = 50;

function toMember(row: MemberRow): StoredMember {
  return { scope: row.scope, userId: row.userId, role: row.role };
}

/** The `MembershipStore` on the membership tables from `prisma/auth.prisma`. */
export class PrismaMembershipStore implements MembershipStore {
  constructor(private readonly delegates: PrismaMembershipDelegates) {}

  async findMember(scope: string, userId: string): Promise<StoredMember | null> {
    const row = (await this.delegates.member.findUnique({
      where: { scope_userId: { scope, userId } },
    })) as MemberRow | null;

    return row ? toMember(row) : null;
  }

  async listMembers(scope: string): Promise<StoredMember[]> {
    const rows = (await this.delegates.member.findMany({ where: { scope } })) as MemberRow[];

    return rows.map(toMember);
  }

  async addMember(member: StoredMember): Promise<boolean> {
    // Adding never takes an admin away, so it needs no version check.
    try {
      await this.delegates.member.create({ data: { ...member } });

      return true;
    } catch (error) {
      if (prismaCode(error) === P2002) return false;

      throw error;
    }
  }

  changeRole(input: {
    readonly scope: string;
    readonly userId: string;
    readonly from: string;
    readonly to: string;
    readonly adminRoles: readonly string[];
  }): Promise<MemberWrite> {
    return this.guarded(input, input.to);
  }

  removeMember(input: {
    readonly scope: string;
    readonly userId: string;
    readonly from: string;
    readonly adminRoles: readonly string[];
  }): Promise<MemberWrite> {
    return this.guarded(input, null);
  }

  /** A role change to `to`, or a removal when `to` is null. */
  private async guarded(
    input: {
      readonly scope: string;
      readonly userId: string;
      readonly from: string;
      readonly adminRoles: readonly string[];
    },
    to: string | null,
  ): Promise<MemberWrite> {
    const { scope, userId, from, adminRoles } = input;
    const key = { scope_userId: { scope, userId } };

    for (let attempt = 1; ; attempt++) {
      // The version first: a write that commits after this read fails the guard.
      const version = await this.versionOf(scope);
      const row = (await this.delegates.member.findUnique({ where: key })) as MemberRow | null;

      if (!row) return 'missing';
      if (row.role !== from) return 'stale';

      if (adminRoles.includes(from) && (to === null || !adminRoles.includes(to))) {
        const others = await this.delegates.member.count({
          where: { scope, userId: { not: userId }, role: { in: [...adminRoles] } },
        });

        if (others === 0) return 'last_admin';
      }

      const write =
        to === null
          ? this.delegates.member.delete({ where: { ...key, role: from } })
          : this.delegates.member.update({ where: { ...key, role: from }, data: { role: to } });

      if (await this.commit(scope, version, write)) return 'done';

      if (attempt >= MAX_ATTEMPTS)
        throw new Error(`Membership write lost the race ${MAX_ATTEMPTS} times; try again`);
    }
  }

  /** The scope row's version, or null when the scope has never had a guarded write. */
  private async versionOf(scope: string): Promise<number | null> {
    const row = (await this.delegates.scope.findUnique({ where: { scope } })) as {
      version: number;
    } | null;

    return row ? row.version : null;
  }

  /** Bumps the version it read and applies `write` in one transaction; false when another write won. */
  private async commit(
    scope: string,
    version: number | null,
    write: PromiseLike<unknown>,
  ): Promise<boolean> {
    const bump =
      version === null
        ? this.delegates.scope.create({ data: { scope, version: 1 } })
        : this.delegates.scope.update({
            where: { scope, version },
            data: { version: version + 1 },
          });

    try {
      await this.delegates.client.$transaction([bump, write]);

      return true;
    } catch (error) {
      const kind = prismaCode(error);

      // P2025: the version moved, or the member changed. P2002: a concurrent
      // first write created the scope row. Either way, decide again.
      if (kind === P2025 || kind === P2002) return false;

      throw error;
    }
  }
}
