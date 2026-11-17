/**
 * The counter-store keys the throttle reads and writes, in one place so the
 * key scheme can be read (and audited) at a glance. Every account key is
 * derived from the normalised email, never the user id, so a known and an
 * unknown address do identical work.
 */
import { sha256Hex } from '../crypto/hash';

/** Store key for an account derived from its normalised email. */
export function accountKey(normalizedEmail: string): string {
  return sha256Hex(`account:${normalizedEmail}`);
}

export const counterKeys = {
  /** A fixed-window rate limit for one door and caller. */
  rateLimit: (scope: string) => `rl:${scope}`,
  /** Present while the account is locked; its TTL is the lock. */
  lock: (account: string) => `lock:${account}`,
  /** Attempts from one IP against one account. */
  accountIp: (account: string, ip: string) => `aip:${account}:${ip}`,
  /** Attempts against one account from every source. */
  account: (account: string) => `acct:${account}`,
  /** The backoff tier: how many locks in a row, renewed on each one. */
  tier: (account: string) => `tier:${account}`,
  /** One trusted device's attempts under a lock. */
  device: (account: string, deviceId: string) => `dev:${account}:${deviceId}`,
  /** The budget shared by all of an account's trusted devices under a lock. */
  devices: (account: string) => `devs:${account}`,
  /** The scope of a second factor's lock, tier and attempts: never an account's own keys. */
  factor: (account: string) => `2fa:${account}`,
} as const;
