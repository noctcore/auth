/**
 * The two-factor plugin's store on the tables from `prisma/auth.prisma`.
 *
 * Every compare-and-set is one guarded `updateMany` (the guard in `where`), so
 * the database decides which of two concurrent callers wins: a time step only
 * moves forward, and a pending factor is confirmed only against the secret it
 * still holds. The recovery codes of a user are one row, replaced by one
 * upsert (an empty set too, so the version never starts over), and a code is
 * spent by an update guarded on the row's version, retried when another write
 * got there first.
 */
import type {
  StoredStepUp,
  StoredTotpFactor,
  StoredTrustedDevice,
  TwoFactorStore,
} from '@noctcore/auth';
import type { PrismaTwoFactorDelegates } from './delegates';
import { P2002, prismaCode } from './prisma-errors';

interface FactorRow {
  userId: string;
  secret: string;
  confirmed: boolean;
  lastStep: number;
  createdAt: Date;
}

interface CodesRow {
  hashes: unknown;
  version: number;
}

interface DeviceRow {
  hash: string;
  userId: string;
  epoch: number;
  createdAt: Date;
  expiresAt: Date;
}

interface StepUpRow {
  sessionId: string;
  userId: string;
  expiresAt: Date;
}

function toHashes(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function toDevice(row: DeviceRow): StoredTrustedDevice {
  return {
    userId: row.userId,
    hash: row.hash,
    epoch: row.epoch,
    createdAt: row.createdAt.getTime(),
    expiresAt: row.expiresAt.getTime(),
  };
}

/** The `TwoFactorStore` on the two-factor tables from `prisma/auth.prisma`. */
export class PrismaTwoFactorStore implements TwoFactorStore {
  constructor(private readonly delegates: PrismaTwoFactorDelegates) {}

  async findFactor(userId: string): Promise<StoredTotpFactor | null> {
    const row = (await this.delegates.factor.findUnique({ where: { userId } })) as FactorRow | null;

    if (!row) return null;

    return {
      userId: row.userId,
      secret: row.secret,
      confirmed: row.confirmed,
      lastStep: row.lastStep,
      createdAt: row.createdAt.getTime(),
    };
  }

  async putPendingFactor(factor: {
    readonly userId: string;
    readonly secret: string;
    readonly createdAt: number;
  }): Promise<boolean> {
    const values = { secret: factor.secret, createdAt: new Date(factor.createdAt), lastStep: -1 };

    // Replace a pending row; a confirmed one is left alone. When there is no
    // row, insert; if a concurrent insert won, try the guarded update again.
    for (;;) {
      const replaced = await this.delegates.factor.updateMany({
        where: { userId: factor.userId, confirmed: false },
        data: values,
      });

      if (replaced.count === 1) return true;

      try {
        await this.delegates.factor.create({
          data: { userId: factor.userId, confirmed: false, ...values },
        });

        return true;
      } catch (error) {
        if (prismaCode(error) !== P2002) throw error;

        const existing = (await this.delegates.factor.findUnique({
          where: { userId: factor.userId },
        })) as FactorRow | null;

        if (existing?.confirmed === true) return false;
      }
    }
  }

  async confirmFactor(userId: string, secret: string, step: number): Promise<boolean> {
    const result = await this.delegates.factor.updateMany({
      where: { userId, confirmed: false, secret },
      data: { confirmed: true, lastStep: step },
    });

    return result.count === 1;
  }

  async advanceStep(userId: string, step: number): Promise<boolean> {
    const result = await this.delegates.factor.updateMany({
      where: { userId, confirmed: true, lastStep: { lt: step } },
      data: { lastStep: step },
    });

    return result.count === 1;
  }

  async deleteFactor(userId: string): Promise<void> {
    await this.delegates.factor.deleteMany({ where: { userId } });
  }

  async replaceRecoveryCodes(userId: string, hashes: readonly string[]): Promise<void> {
    // An empty set is written as an empty row, never a delete: the version only
    // grows for as long as the user exists, so a spend that read an old set
    // can never match a newer row that happens to start at the same version.
    const args = {
      where: { userId },
      create: { userId, hashes: [...hashes], version: 0 },
      update: { hashes: [...hashes], version: { increment: 1 } },
    };

    try {
      await this.delegates.recoveryCodes.upsert(args);
    } catch (error) {
      // Two concurrent first writes can both try to insert; the loser updates instead.
      if (prismaCode(error) !== P2002) throw error;

      await this.delegates.recoveryCodes.upsert(args);
    }
  }

  async consumeRecoveryCode(userId: string, hash: string): Promise<boolean> {
    // Compare-and-set on the version: only the caller whose update matched the
    // version it read removes the code. A loser reads again and finds it gone
    // (or another code spent, and tries once more).
    for (;;) {
      const row = (await this.delegates.recoveryCodes.findUnique({
        where: { userId },
      })) as CodesRow | null;

      const hashes = toHashes(row?.hashes);
      // A lookup by HMAC, as a WHERE on the column would be: the stored value
      // is keyed by the server secret, so its timing tells a guesser nothing.
      const index = hashes.indexOf(hash);

      if (!row || index === -1) return false;

      const spent = await this.delegates.recoveryCodes.updateMany({
        where: { userId, version: row.version },
        data: { hashes: hashes.filter((_, at) => at !== index), version: row.version + 1 },
      });

      if (spent.count === 1) return true;
    }
  }

  async countRecoveryCodes(userId: string): Promise<number> {
    const row = (await this.delegates.recoveryCodes.findUnique({
      where: { userId },
    })) as CodesRow | null;

    return toHashes(row?.hashes).length;
  }

  async addTrustedDevice(device: StoredTrustedDevice, maxPerUser: number): Promise<void> {
    // The device was trusted just now: its creation time is the clock's.
    const now = new Date(device.createdAt);

    await this.delegates.trustedDevice.create({
      data: {
        hash: device.hash,
        userId: device.userId,
        epoch: device.epoch,
        createdAt: new Date(device.createdAt),
        expiresAt: new Date(device.expiresAt),
      },
    });

    const beyond = (await this.delegates.trustedDevice.findMany({
      where: { userId: device.userId },
      orderBy: { createdAt: 'desc' },
      skip: maxPerUser,
      select: { hash: true },
    })) as Array<{ hash: string }>;

    await this.delegates.trustedDevice.deleteMany({
      where: {
        userId: device.userId,
        OR: [{ hash: { in: beyond.map((d) => d.hash) } }, { expiresAt: { lte: now } }],
      },
    });
  }

  async findTrustedDevice(userId: string, hash: string): Promise<StoredTrustedDevice | null> {
    const row = (await this.delegates.trustedDevice.findUnique({
      where: { hash },
    })) as DeviceRow | null;

    return row?.userId === userId ? toDevice(row) : null;
  }

  async deleteTrustedDevices(userId: string): Promise<void> {
    await this.delegates.trustedDevice.deleteMany({ where: { userId } });
  }

  async putStepUp(stepUp: StoredStepUp): Promise<void> {
    const values = { userId: stepUp.userId, expiresAt: new Date(stepUp.expiresAt) };

    await this.delegates.stepUp.upsert({
      where: { sessionId: stepUp.sessionId },
      create: { sessionId: stepUp.sessionId, ...values },
      update: values,
    });
  }

  async findStepUp(sessionId: string): Promise<StoredStepUp | null> {
    const row = (await this.delegates.stepUp.findUnique({
      where: { sessionId },
    })) as StepUpRow | null;

    return row
      ? { sessionId: row.sessionId, userId: row.userId, expiresAt: row.expiresAt.getTime() }
      : null;
  }
}
