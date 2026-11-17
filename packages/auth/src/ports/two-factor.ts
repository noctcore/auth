/**
 * The contracts the two-factor plugin (`@noctcore/auth/two-factor`) is handed:
 * the store for its factors, recovery codes, trusted devices and step-up
 * proofs, and the cipher that keeps TOTP secrets encrypted at rest.
 *
 * Every write that must not happen twice is atomic, and the conformance suite
 * in `@noctcore/auth/testing` (`twoFactorStoreConformance`) checks it:
 *
 * - the last accepted time step only moves forward, by compare-and-set, so a
 *   TOTP code cannot be accepted twice, not even by two requests at once;
 * - confirming an enrollment is a compare-and-set on the pending secret, so a
 *   code for a secret that was replaced meanwhile never activates the new one;
 * - a recovery code is consumed by one atomic step: of many concurrent callers
 *   exactly one gets it, and replacing the set voids every old code at once.
 *
 * Guide: Learn, "Second factors"; Build, "Two-factor".
 */

/** A user's TOTP factor. Pending until a code from it is confirmed. */
export interface StoredTotpFactor {
  readonly userId: string;
  /** The secret as the cipher wrote it. Never the raw secret. */
  readonly secret: string;
  /** False while enrollment waits for its first code; only a confirmed factor guards a login. */
  readonly confirmed: boolean;
  /** The last accepted time step (Unix time / 30 s); -1 before any. A code at or before it is refused. */
  readonly lastStep: number;
  /** When the secret was generated, in ms since the epoch. */
  readonly createdAt: number;
}

/** A device that may skip the login challenge. Only the SHA-256 of its token is stored. */
export interface StoredTrustedDevice {
  readonly userId: string;
  /** SHA-256 of the device token. */
  readonly hash: string;
  /** The user's revocation epoch when it was trusted: any later revoke-all voids it. */
  readonly epoch: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/** A recent second-factor proof for one session. */
export interface StoredStepUp {
  readonly sessionId: string;
  readonly userId: string;
  readonly expiresAt: number;
}

export interface TwoFactorStore {
  findFactor(userId: string): Promise<StoredTotpFactor | null>;
  /**
   * Stores a pending (unconfirmed) factor with `lastStep` -1, replacing a
   * pending one. Never replaces a confirmed factor: returns false (and writes
   * nothing) when the user has one.
   */
  putPendingFactor(factor: {
    readonly userId: string;
    readonly secret: string;
    readonly createdAt: number;
  }): Promise<boolean>;
  /**
   * Compare-and-set: confirms the factor and sets `lastStep` to `step` only if
   * it is still pending and its secret still equals `secret`, in one atomic
   * write. Returns whether it did.
   */
  confirmFactor(userId: string, secret: string, step: number): Promise<boolean>;
  /**
   * Compare-and-set: sets `lastStep` to `step` only if the factor is confirmed
   * and its `lastStep` is below `step`, in one atomic write. Of many
   * concurrent callers with the same step, at most one gets true.
   */
  advanceStep(userId: string, step: number): Promise<boolean>;
  /** Deletes the factor, pending or confirmed. */
  deleteFactor(userId: string): Promise<void>;
  /** Replaces the user's recovery codes with `hashes` in one atomic write (an empty list deletes them). */
  replaceRecoveryCodes(userId: string, hashes: readonly string[]): Promise<void>;
  /** Removes one recovery code atomically: of many concurrent callers exactly one gets true. */
  consumeRecoveryCode(userId: string, hash: string): Promise<boolean>;
  countRecoveryCodes(userId: string): Promise<number>;
  /**
   * Stores a trusted device, then deletes the user's oldest devices beyond
   * `maxPerUser`. May drop it after `expiresAt`.
   */
  addTrustedDevice(device: StoredTrustedDevice, maxPerUser: number): Promise<void>;
  /** The device with this hash if it belongs to `userId` (expired or not: the caller checks). */
  findTrustedDevice(userId: string, hash: string): Promise<StoredTrustedDevice | null>;
  deleteTrustedDevices(userId: string): Promise<void>;
  /** Stores (or replaces) the step-up proof of a session. May drop it after `expiresAt`. */
  putStepUp(stepUp: StoredStepUp): Promise<void>;
  /** The session's step-up proof (expired or not: the caller checks). */
  findStepUp(sessionId: string): Promise<StoredStepUp | null>;
}

/**
 * Encrypts TOTP secrets for storage. The app owns the key and its rotation
 * (an AES-256-GCM key from a KMS or the environment, for example); the plugin
 * never handles key material. `userId` is there to bind each ciphertext to its
 * row (as associated data), so a secret copied onto another user's row does not
 * decrypt.
 */
export interface SecretCipher {
  encrypt(secret: Uint8Array, context: { readonly userId: string }): Promise<string>;
  decrypt(ciphertext: string, context: { readonly userId: string }): Promise<Uint8Array>;
}
