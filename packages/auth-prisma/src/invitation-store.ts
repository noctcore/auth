/**
 * The invitations plugin's store on the `AuthInvitation` table from
 * `prisma/auth.prisma`.
 *
 * - `consume` is one `DELETE ... RETURNING` by the unique hash: of many
 *   concurrent callers exactly one deletes the row, the others find none.
 * - `create` relies on the unique (scope, email) index: a concurrent create for
 *   the same pair fails with P2002 and answers false. An expired row for the
 *   pair is deleted and the new one inserted in one transaction, so a live
 *   invitation inserted meanwhile rolls the delete back too.
 *
 * Expired rows stay until they are replaced, consumed or revoked; sweep them
 * with `deleteMany({ where: { expiresAt: { lte: new Date() } } })` if needed.
 */
import type { InvitationStore, StoredInvitation } from '@noctcore/auth';
import type { PrismaInvitationDelegates } from './delegates';
import { P2002, P2025, prismaCode } from './prisma-errors';

interface InvitationRow {
  id: string;
  hash: string;
  scope: string;
  email: string;
  inviterId: string;
  payload: unknown;
  createdAt: Date;
  expiresAt: Date;
}

/** Retries before a create that keeps meeting a replaced or vanishing row gives up. */
const MAX_ATTEMPTS = 5;

function toInvitation(row: InvitationRow): StoredInvitation {
  return {
    id: row.id,
    hash: row.hash,
    scope: row.scope,
    email: row.email,
    inviterId: row.inviterId,
    payload: { ...(row.payload as Record<string, string>) },
    createdAt: row.createdAt.getTime(),
    expiresAt: row.expiresAt.getTime(),
  };
}

function toRow(invitation: StoredInvitation): InvitationRow {
  return {
    ...invitation,
    payload: { ...invitation.payload },
    createdAt: new Date(invitation.createdAt),
    expiresAt: new Date(invitation.expiresAt),
  };
}

/** The `InvitationStore` on the `AuthInvitation` table from `prisma/auth.prisma`. */
export class PrismaInvitationStore implements InvitationStore {
  constructor(private readonly delegates: PrismaInvitationDelegates) {}

  async create(invitation: StoredInvitation, now: number): Promise<boolean> {
    const { client, invitation: table } = this.delegates;
    const data = toRow(invitation);

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const existing = (await table.findUnique({
        where: { scope_email: { scope: invitation.scope, email: invitation.email } },
      })) as InvitationRow | null;

      if (existing && existing.expiresAt.getTime() > now) return false;

      try {
        await client.$transaction([
          table.deleteMany({
            where: {
              scope: invitation.scope,
              email: invitation.email,
              expiresAt: { lte: new Date(now) },
            },
          }),
          table.create({ data }),
        ]);

        return true;
      } catch (error) {
        // A concurrent create for the pair won: decide again on the row it wrote.
        if (prismaCode(error) !== P2002) throw error;
      }
    }

    throw new Error(`Invitation create lost the race ${MAX_ATTEMPTS} times; try again`);
  }

  async findByHash(hash: string): Promise<StoredInvitation | null> {
    const row = (await this.delegates.invitation.findUnique({
      where: { hash },
    })) as InvitationRow | null;

    return row ? toInvitation(row) : null;
  }

  async consume(hash: string): Promise<StoredInvitation | null> {
    try {
      const row = (await this.delegates.invitation.delete({ where: { hash } })) as InvitationRow;

      return toInvitation(row);
    } catch (error) {
      if (prismaCode(error) === P2025) return null;

      throw error;
    }
  }

  async listByScope(scope: string, now: number): Promise<StoredInvitation[]> {
    const rows = (await this.delegates.invitation.findMany({
      where: { scope, expiresAt: { gt: new Date(now) } },
    })) as InvitationRow[];

    return rows.map(toInvitation);
  }

  async revoke(scope: string, id: string): Promise<boolean> {
    const { count } = await this.delegates.invitation.deleteMany({ where: { scope, id } });

    return count > 0;
  }

  async deleteByInviter(inviterId: string, scope?: string): Promise<void> {
    await this.delegates.invitation.deleteMany({
      where: scope === undefined ? { inviterId } : { inviterId, scope },
    });
  }
}
