import { describe, expect, it } from 'vitest';

import { deriveKey, toSecret } from '../../src/crypto/keys';
import { AuthConfigError } from '../../src/shared/errors';

describe('toSecret', () => {
  it('refuses a missing secret and one shorter than 32 bytes, as a string or as bytes', () => {
    expect(() => toSecret(undefined)).toThrow(AuthConfigError);
    expect(() => toSecret('x'.repeat(31))).toThrow(/at least 32 bytes/u);
    expect(() => toSecret(new Uint8Array(31))).toThrow(/at least 32 bytes/u);
  });

  it('counts UTF-8 bytes, not characters, and keeps bytes as given', () => {
    // 11 three-byte characters are 33 bytes.
    expect(toSecret('€'.repeat(11)).byteLength).toBe(33);
    expect(() => toSecret('€'.repeat(10))).toThrow(AuthConfigError);

    const bytes = new Uint8Array(32).fill(7);

    expect(toSecret(bytes)).toBe(bytes);
  });
});

describe('deriveKey', () => {
  const secret = toSecret('s'.repeat(32));

  it('gives each purpose its own stable key', () => {
    expect(deriveKey(secret, 'device')).toEqual(deriveKey(secret, 'device'));
    expect(deriveKey(secret, 'device')).not.toEqual(deriveKey(secret, 'csrf'));
  });

  it('depends on the secret', () => {
    expect(deriveKey(secret, 'device')).not.toEqual(deriveKey(toSecret('t'.repeat(32)), 'device'));
  });
});
