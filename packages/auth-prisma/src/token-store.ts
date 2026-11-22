/**
 * The `TokenStore` on the `AuthToken` model from `prisma/auth.prisma`. Consume
 * is a delete that returns the row, so only one caller ever gets a token, the
 * attempt cap is an update whose `where` carries the cap, and an extend is an
 * update that fails on a missing row instead of an upsert.
 */
import type { StoredToken, TokenStore } from '@noctcore/auth';
import type { PrismaAuthTokenDelegate } from './delegates';
import { P2002, P2025, prismaCode } from './prisma-errors';

interface TokenRow {
  purpose: string;
  userId: string;
  hash: string;
  expiresAt: Date;
  attempts: number;
  data: unknown;
}

function toToken(row: TokenRow | null): StoredToken | null {
  if (!row) return null;

  const data =
    row.data && typeof row.data === 'object' && !Array.isArray(row.data)
      ? (row.data as Record<string, string>)
      : {};

  return {
    purpose: row.purpose,
    userId: row.userId,
    hash: row.hash,
    expiresAt: row.expiresAt.getTime(),
    attempts: row.attempts,
    data,
  };
}

/** The `TokenStore` on the `AuthToken` model from `prisma/auth.prisma`. */
export class PrismaTokenStore implements TokenStore {
  constructor(private readonly delegate: PrismaAuthTokenDelegate) {}

  async put(token: StoredToken): Promise<void> {
    const values = {
      hash: token.hash,
      expiresAt: new Date(token.expiresAt),
      attempts: token.attempts,
      data: { ...token.data },
    };

    const args = {
      where: { userId_purpose: { userId: token.userId, purpose: token.purpose } },
      create: { userId: token.userId, purpose: token.purpose, ...values },
      update: values,
    };

    try {
      await this.delegate.upsert(args);
    } catch (error) {
      // Two concurrent first puts can both try to insert; the loser updates instead.
      if (prismaCode(error) !== P2002) throw error;

      await this.delegate.upsert(args);
    }
  }

  async find(purpose: string, hash: string): Promise<StoredToken | null> {
    const row = (await this.delegate.findUnique({
      where: { purpose_hash: { purpose, hash } },
    })) as TokenRow | null;

    return toToken(row);
  }

  async findByUser(purpose: string, userId: string): Promise<StoredToken | null> {
    const row = (await this.delegate.findUnique({
      where: { userId_purpose: { userId, purpose } },
    })) as TokenRow | null;

    return toToken(row);
  }

  async consume(purpose: string, hash: string): Promise<StoredToken | null> {
    try {
      // The delete returns the row it removed, so only one caller ever gets it.
      const row = (await this.delegate.delete({
        where: { purpose_hash: { purpose, hash } },
      })) as TokenRow;

      return toToken(row);
    } catch (error) {
      if (prismaCode(error) === P2025) return null;

      throw error;
    }
  }

  async extendExpiry(purpose: string, hash: string, expiresAt: number): Promise<boolean> {
    try {
      // An update, not an upsert: a row consumed meanwhile is not created again.
      await this.delegate.update({
        where: { purpose_hash: { purpose, hash } },
        data: { expiresAt: new Date(expiresAt) },
        select: { hash: true },
      });

      return true;
    } catch (error) {
      if (prismaCode(error) === P2025) return false;

      throw error;
    }
  }

  async incrementAttempts(purpose: string, userId: string, max: number): Promise<number | null> {
    try {
      const row = (await this.delegate.update({
        where: { userId_purpose: { userId, purpose }, attempts: { lt: max } },
        data: { attempts: { increment: 1 } },
        select: { attempts: true },
      })) as { attempts: number };

      return row.attempts;
    } catch (error) {
      if (prismaCode(error) === P2025) return null;

      throw error;
    }
  }

  async deleteByUser(userId: string, purposes?: readonly string[]): Promise<void> {
    await this.delegate.deleteMany({
      where: purposes ? { userId, purpose: { in: [...purposes] } } : { userId },
    });
  }
}
