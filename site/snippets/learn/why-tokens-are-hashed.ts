import { generateToken, isTokenShape, sha256Hex } from '@noctcore/auth';

// A token of the app's own (an API key, say), kept the way the package keeps
// sessions and links: the holder gets the token once, the store gets its
// SHA-256, and the hash is the key it is found by.
export function issueApiKey(): { token: string; storeKey: string } {
  const token = generateToken();

  return { token, storeKey: sha256Hex(token) };
}

// Nothing to compare: the presented value is hashed and looked up. A leaked
// store key sent back as a token hashes to a key no row has.
export function storeKeyFor(presented: string): string | undefined {
  return isTokenShape(presented) ? sha256Hex(presented) : undefined;
}
