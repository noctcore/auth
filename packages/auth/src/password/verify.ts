/**
 * Checks a password against a stored hash at a cost that does not depend on
 * whether there is a hash at all.
 *
 * An account without a password (or no account) and an oversized input are
 * still sent through the hasher, against a dummy hash, so how long a refusal
 * takes says nothing about the account.
 */
import { dummyHashFor, type PasswordHasher } from './hasher';
import { checkPasswordPolicy, normalizePassword, type PasswordPolicy } from './policy';

export async function verifyPasswordHash(
  hasher: PasswordHasher,
  policy: PasswordPolicy,
  passwordHash: string | null | undefined,
  password: string,
): Promise<boolean> {
  // An oversized input is never a valid password; verify an empty one so the
  // hasher's cost stays bounded and the timing stays the same.
  const tooLong = checkPasswordPolicy(password, policy) === 'too_long';
  const normalized = tooLong ? '' : normalizePassword(password);

  if (!passwordHash || tooLong) {
    // Pay the same verify cost as a real account, and discard the result,
    // so even a preimage of the dummy hash can never authenticate.
    const dummyHash = await dummyHashFor(hasher);

    await hasher.verify(dummyHash, normalized);

    return false;
  }

  return hasher.verify(passwordHash, normalized);
}
