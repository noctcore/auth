/**
 * The password hashing contract. The default implementation is Argon2id
 * (`@noctcore/auth/argon2`); anything that meets this interface can replace it.
 *
 * Flows hand the hasher the NFC-normalised password, so implementations never
 * normalise themselves.
 *
 * Guide: Learn, "Passwords".
 */
export interface PasswordHasher {
  hash(password: string): Promise<string>;
  /** False for a wrong password AND for a stored hash it cannot parse; never throws for either. */
  verify(hash: string, password: string): Promise<boolean>;
  /**
   * Whether a hash that just verified was made with other parameters than the
   * hasher's current ones. Login rehashes when this is true, so raising the
   * cost later upgrades every active account without a migration.
   */
  needsRehash(hash: string): boolean;
}

const dummyHashes = new WeakMap<PasswordHasher, Promise<string>>();

/**
 * A hash of a random throwaway value made by THIS hasher with its current
 * parameters. Login verifies against it when the email is unknown (or the
 * account has no password), so that branch pays exactly the cost of a real
 * verify and response time does not reveal whether the account exists.
 *
 * Computed once per hasher and cached. Because it comes from the hasher itself,
 * it can never drift from the configured parameters.
 */
export function dummyHashFor(hasher: PasswordHasher): Promise<string> {
  let cached = dummyHashes.get(hasher);

  if (!cached) {
    const bytes = new Uint8Array(24);

    globalThis.crypto.getRandomValues(bytes);
    cached = hasher.hash(Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''));
    // A failed computation must not be cached forever.
    cached.catch(() => dummyHashes.delete(hasher));
    dummyHashes.set(hasher, cached);
  }

  return cached;
}
