/**
 * Argon2id password hashing on `@node-rs/argon2` (an optional peer dependency:
 * install it to use this entry point).
 *
 * The defaults are OWASP's floor (19 MiB, 2 passes, 1 lane). Parameters below
 * every row of OWASP's equivalence table are refused unless the caller opts in
 * explicitly, which only tests should do. Raise the cost per box; login
 * rehashes old hashes with `needsRehash`, so raising it later costs nothing.
 *
 * Guide: Learn, "Password hashing".
 */
import { hash, verify } from '@node-rs/argon2';

import { AuthConfigError } from './errors';
import type { PasswordHasher } from './password/hasher';

export interface Argon2idOptions {
  /** KiB of memory. Default 19456 (19 MiB). */
  readonly memoryCost?: number;
  /** Passes. Default 2. */
  readonly timeCost?: number;
  /** Lanes. Default 1. */
  readonly parallelism?: number;
  /**
   * Optional pepper (Argon2's secret input), kept outside the database.
   * Changing or losing it makes every existing hash unverifiable, and
   * `needsRehash` cannot detect a pepper change.
   */
  readonly secret?: Uint8Array;
  /** Allow parameters below OWASP's table. Tests only. */
  readonly unsafeAllowWeakParameters?: boolean;
}

export const OWASP_ARGON2ID = { memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

// OWASP Password Storage Cheat Sheet: equivalent Argon2id configurations,
// memory (KiB) to the minimum passes that make it acceptable.
const OWASP_TABLE: ReadonlyArray<readonly [memory: number, passes: number]> = [
  [47_104, 1],
  [19_456, 2],
  [12_288, 3],
  [9_216, 4],
  [7_168, 5],
];

const ARGON2ID = 2; // Algorithm.Argon2id; a const enum, so the number is used directly.
const PHC = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/u;

export function argon2id(options: Argon2idOptions = {}): PasswordHasher {
  const memoryCost = options.memoryCost ?? OWASP_ARGON2ID.memoryCost;
  const timeCost = options.timeCost ?? OWASP_ARGON2ID.timeCost;
  const parallelism = options.parallelism ?? OWASP_ARGON2ID.parallelism;
  const acceptable = OWASP_TABLE.some(([m, t]) => memoryCost >= m && timeCost >= t);
  if (!acceptable && options.unsafeAllowWeakParameters !== true) {
    throw new AuthConfigError(
      `Argon2id m=${memoryCost} t=${timeCost} is below the OWASP minimum (for example m=19456 t=2)`,
    );
  }
  const params = {
    algorithm: ARGON2ID,
    memoryCost,
    timeCost,
    parallelism,
    ...(options.secret ? { secret: options.secret } : {}),
  };

  return {
    hash: (password) => hash(password, params),
    async verify(stored, password) {
      try {
        return await verify(stored, password, options.secret ? { secret: options.secret } : undefined);
      } catch {
        // A malformed stored hash (bad import or migration) is not a correct
        // password. The flow logs it through needsRehash's caller; no secret
        // material is in the error.
        return false;
      }
    },
    needsRehash(stored) {
      const match = PHC.exec(stored);
      if (!match) return true;
      return (
        Number(match[1]) !== memoryCost || Number(match[2]) !== timeCost || Number(match[3]) !== parallelism
      );
    },
  };
}
