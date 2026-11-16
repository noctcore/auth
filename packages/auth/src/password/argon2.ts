/**
 * Argon2id password hashing on `@node-rs/argon2` (an optional peer dependency:
 * install it to use this entry point).
 *
 * The defaults (19 MiB, 3 passes, 1 lane) meet both published floors: OWASP's
 * (19 MiB with 2 passes) and the auth guide's (16 MiB with 3 passes). Where the
 * two disagree the stricter value wins, so memory comes from OWASP and passes
 * from the guide. Parameters below every row of OWASP's equivalence table are
 * refused unless the caller opts in explicitly, which only tests should do.
 * Raise the memory per box; login rehashes old hashes with `needsRehash`, so
 * raising it later (or adopting hashes made with t=2) costs nothing.
 *
 * Hashing is CPU and memory heavy: every door that hashes a password is rate
 * limited by the flows, so it cannot be used to exhaust the server.
 *
 * Guide: Learn, "Password hashing".
 */
import { hash, verify } from '@node-rs/argon2';
import type { PasswordHasher } from './hasher';
import { AuthConfigError } from '../shared/errors';

export interface Argon2idOptions {
  /** KiB of memory. Default 19456 (19 MiB). */
  readonly memoryCost?: number;
  /** Passes. Default 3. */
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

/** OWASP's floor, the least the hasher accepts without `unsafeAllowWeakParameters`. */
export const OWASP_ARGON2ID = { memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

/** The default: OWASP's memory with the auth guide's three passes. */
export const DEFAULT_ARGON2ID = { memoryCost: 19_456, timeCost: 3, parallelism: 1 } as const;

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
  const memoryCost = options.memoryCost ?? DEFAULT_ARGON2ID.memoryCost;
  const timeCost = options.timeCost ?? DEFAULT_ARGON2ID.timeCost;
  const parallelism = options.parallelism ?? DEFAULT_ARGON2ID.parallelism;
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
        return await verify(
          stored,
          password,
          options.secret ? { secret: options.secret } : undefined,
        );
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
        Number(match[1]) !== memoryCost ||
        Number(match[2]) !== timeCost ||
        Number(match[3]) !== parallelism
      );
    },
  };
}
