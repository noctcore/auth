/**
 * An in-memory TwoFactorStore with the guarantees the conformance suite asks
 * of real adapters: every compare-and-set and every consume happens without an
 * await in the middle, so it is atomic on the event loop. For unit tests and
 * prototypes only.
 */
import type {
  StoredStepUp,
  StoredTotpFactor,
  StoredTrustedDevice,
  TwoFactorStore,
} from '../../ports/two-factor';

export class MemoryTwoFactorStore implements TwoFactorStore {
  private readonly factors = new Map<string, StoredTotpFactor>();
  private readonly recoveryCodes = new Map<string, Set<string>>();
  private readonly devices = new Map<string, StoredTrustedDevice>();
  private readonly stepUps = new Map<string, StoredStepUp>();

  async findFactor(userId: string): Promise<StoredTotpFactor | null> {
    const factor = this.factors.get(userId);

    return factor ? { ...factor } : null;
  }

  async putPendingFactor(factor: {
    userId: string;
    secret: string;
    createdAt: number;
  }): Promise<boolean> {
    if (this.factors.get(factor.userId)?.confirmed === true) return false;

    this.factors.set(factor.userId, { ...factor, confirmed: false, lastStep: -1 });

    return true;
  }

  async confirmFactor(userId: string, secret: string, step: number): Promise<boolean> {
    const factor = this.factors.get(userId);

    if (!factor || factor.confirmed || factor.secret !== secret) return false;

    this.factors.set(userId, { ...factor, confirmed: true, lastStep: step });

    return true;
  }

  async advanceStep(userId: string, step: number): Promise<boolean> {
    const factor = this.factors.get(userId);

    if (!factor?.confirmed || factor.lastStep >= step) return false;

    this.factors.set(userId, { ...factor, lastStep: step });

    return true;
  }

  async deleteFactor(userId: string): Promise<void> {
    this.factors.delete(userId);
  }

  async replaceRecoveryCodes(userId: string, hashes: readonly string[]): Promise<void> {
    if (hashes.length === 0) this.recoveryCodes.delete(userId);
    else this.recoveryCodes.set(userId, new Set(hashes));
  }

  async consumeRecoveryCode(userId: string, hash: string): Promise<boolean> {
    return this.recoveryCodes.get(userId)?.delete(hash) ?? false;
  }

  async countRecoveryCodes(userId: string): Promise<number> {
    return this.recoveryCodes.get(userId)?.size ?? 0;
  }

  async addTrustedDevice(device: StoredTrustedDevice, maxPerUser: number): Promise<void> {
    this.devices.set(device.hash, { ...device });

    // Newest first; among equal timestamps the later insert counts as newer.
    const own = [...this.devices.values()]
      .filter((d) => d.userId === device.userId)
      .reverse()
      .sort((a, b) => b.createdAt - a.createdAt);

    for (const old of own.slice(maxPerUser)) this.devices.delete(old.hash);
  }

  async findTrustedDevice(userId: string, hash: string): Promise<StoredTrustedDevice | null> {
    const device = this.devices.get(hash);

    return device?.userId === userId ? { ...device } : null;
  }

  async deleteTrustedDevices(userId: string): Promise<void> {
    for (const [hash, device] of this.devices) {
      if (device.userId === userId) this.devices.delete(hash);
    }
  }

  async putStepUp(stepUp: StoredStepUp): Promise<void> {
    this.stepUps.set(stepUp.sessionId, { ...stepUp });
  }

  async findStepUp(sessionId: string): Promise<StoredStepUp | null> {
    const stepUp = this.stepUps.get(sessionId);

    return stepUp ? { ...stepUp } : null;
  }
}
