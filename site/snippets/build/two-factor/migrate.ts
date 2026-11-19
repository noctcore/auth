import type { SecretCipher, TwoFactorStore } from '@noctcore/auth';
import { importedRecoveryCodeHashes } from '@noctcore/auth/two-factor';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decodes an RFC 4648 base32 TOTP seed, the form authenticator apps were given. */
function decodeBase32(seed: string): Uint8Array {
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const char of seed.toUpperCase().replace(/[\s=]/g, '')) {
    const value = BASE32.indexOf(char);

    if (value === -1) throw new Error('Not a base32 seed');

    buffer = (buffer << 5) | value;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Moves one user's existing TOTP seed into the plugin's store, already
 * confirmed, so their authenticator app keeps working. Run it once per user,
 * from a script, before you turn the plugin on.
 */
export async function migrateTotpSeed(
  store: TwoFactorStore,
  cipher: SecretCipher,
  user: { id: string; totpSeed: string },
): Promise<void> {
  const secret = await cipher.encrypt(decodeBase32(user.totpSeed), { userId: user.id });

  if (!(await store.putPendingFactor({ userId: user.id, secret, createdAt: Date.now() }))) return;

  // The last accepted step starts two steps back, so the code on the user's
  // phone right now is accepted at their next login.
  const step = Math.floor(Date.now() / 30_000) - 2;

  await store.confirmFactor(user.id, secret, step);
}

/**
 * Carries one user's unused recovery codes over as the old app stored them
 * (here the hex SHA-256 of each code), replacing whatever set the store held.
 * The plugin accepts them only with its `importedRecoveryCodes` option.
 */
export async function migrateRecoveryCodes(
  store: TwoFactorStore,
  user: { id: string; recoveryCodeHashes: string[] },
): Promise<void> {
  await store.replaceRecoveryCodes(user.id, importedRecoveryCodeHashes(user.recoveryCodeHashes));
}
