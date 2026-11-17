/**
 * The two-factor plugin's store on Redis.
 *
 * - `tf:f:<userId>`   the TOTP factor, a hash (secret, confirmed, lastStep, createdAt);
 * - `tf:r:<userId>`   the recovery code hashes, a set;
 * - `tf:d:<hash>`     a trusted device as JSON, with a TTL at its expiry;
 * - `tf:du:<userId>`  a sorted set of the user's device hashes, scored by creation;
 * - `tf:s:<sessionId>` a step-up proof as JSON, with a TTL at its expiry.
 *
 * Every compare-and-set is one Lua script, so it is atomic. The factor and the
 * recovery codes have no TTL: they are account data, so run Redis with
 * persistence (AOF) if it holds them, or keep them in Postgres
 * (`@noctcore/auth-prisma`) and use Redis for sessions and counters only.
 */
import type {
  Clock,
  StoredStepUp,
  StoredTotpFactor,
  StoredTrustedDevice,
  TwoFactorStore,
} from '@noctcore/auth';
import { systemClock } from '@noctcore/auth';
import type { Redis } from 'ioredis';
import type { RedisStoreOptions } from './options';
import {
  ADD_TRUSTED_DEVICE,
  ADVANCE_STEP,
  CONFIRM_FACTOR,
  DELETE_TRUSTED_DEVICES,
  PUT_PENDING_FACTOR,
  REPLACE_RECOVERY_CODES,
} from './scripts';

/** The `TwoFactorStore` on Redis. */
export class RedisTwoFactorStore implements TwoFactorStore {
  private readonly prefix: string;
  private readonly devicePrefix: string;
  private readonly clock: Clock;

  constructor(
    private readonly redis: Redis,
    options: RedisStoreOptions = {},
  ) {
    this.prefix = `${options.prefix ?? 'auth:'}tf:`;
    this.devicePrefix = `${this.prefix}d:`;
    this.clock = options.clock ?? systemClock;
  }

  private factorKey(userId: string): string {
    return `${this.prefix}f:${userId}`;
  }

  private codesKey(userId: string): string {
    return `${this.prefix}r:${userId}`;
  }

  private devicesKey(userId: string): string {
    return `${this.prefix}du:${userId}`;
  }

  private stepUpKey(sessionId: string): string {
    return `${this.prefix}s:${sessionId}`;
  }

  /** Milliseconds until `expiresAt`, at least 1 (Redis refuses a TTL of 0). */
  private ttl(expiresAt: number): string {
    return String(Math.max(1, Math.ceil(expiresAt - this.clock.now())));
  }

  async findFactor(userId: string): Promise<StoredTotpFactor | null> {
    const fields = await this.redis.hgetall(this.factorKey(userId));

    if (fields['secret'] === undefined) return null;

    return {
      userId,
      secret: fields['secret'],
      confirmed: fields['confirmed'] === '1',
      lastStep: Number(fields['lastStep']),
      createdAt: Number(fields['createdAt']),
    };
  }

  async putPendingFactor(factor: {
    readonly userId: string;
    readonly secret: string;
    readonly createdAt: number;
  }): Promise<boolean> {
    const result = await this.redis.eval(
      PUT_PENDING_FACTOR,
      1,
      this.factorKey(factor.userId),
      factor.secret,
      String(factor.createdAt),
    );

    return result === 1;
  }

  async confirmFactor(userId: string, secret: string, step: number): Promise<boolean> {
    const result = await this.redis.eval(
      CONFIRM_FACTOR,
      1,
      this.factorKey(userId),
      secret,
      String(step),
    );

    return result === 1;
  }

  async advanceStep(userId: string, step: number): Promise<boolean> {
    return (await this.redis.eval(ADVANCE_STEP, 1, this.factorKey(userId), String(step))) === 1;
  }

  async deleteFactor(userId: string): Promise<void> {
    await this.redis.del(this.factorKey(userId));
  }

  async replaceRecoveryCodes(userId: string, hashes: readonly string[]): Promise<void> {
    await this.redis.eval(REPLACE_RECOVERY_CODES, 1, this.codesKey(userId), ...hashes);
  }

  async consumeRecoveryCode(userId: string, hash: string): Promise<boolean> {
    return (await this.redis.srem(this.codesKey(userId), hash)) === 1;
  }

  async countRecoveryCodes(userId: string): Promise<number> {
    return this.redis.scard(this.codesKey(userId));
  }

  async addTrustedDevice(device: StoredTrustedDevice, maxPerUser: number): Promise<void> {
    await this.redis.eval(
      ADD_TRUSTED_DEVICE,
      2,
      `${this.devicePrefix}${device.hash}`,
      this.devicesKey(device.userId),
      JSON.stringify(device),
      this.ttl(device.expiresAt),
      String(device.createdAt),
      device.hash,
      String(maxPerUser),
      this.devicePrefix,
    );
  }

  async findTrustedDevice(userId: string, hash: string): Promise<StoredTrustedDevice | null> {
    const device = parse<StoredTrustedDevice>(await this.redis.get(`${this.devicePrefix}${hash}`));

    return device?.userId === userId ? device : null;
  }

  async deleteTrustedDevices(userId: string): Promise<void> {
    await this.redis.eval(DELETE_TRUSTED_DEVICES, 1, this.devicesKey(userId), this.devicePrefix);
  }

  async putStepUp(stepUp: StoredStepUp): Promise<void> {
    await this.redis.set(
      this.stepUpKey(stepUp.sessionId),
      JSON.stringify(stepUp),
      'PX',
      this.ttl(stepUp.expiresAt),
    );
  }

  async findStepUp(sessionId: string): Promise<StoredStepUp | null> {
    return parse<StoredStepUp>(await this.redis.get(this.stepUpKey(sessionId)));
  }
}

function parse<T>(value: string | null): T | null {
  if (value === null) return null;

  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}
