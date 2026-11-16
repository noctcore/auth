import { describe, expect, it } from 'vitest';

import { hexDigestsEqual, hmacSha256Hex, secretsEqual, sha256Hex } from '../../src/crypto/hash';

describe('sha256Hex', () => {
  it('hashes the UTF-8 string (known vector)', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('hmacSha256Hex', () => {
  it('matches RFC 4231 test case 2', () => {
    const key = new TextEncoder().encode('Jefe');

    expect(hmacSha256Hex(key, 'what do ya want for nothing?')).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });
});

describe('hexDigestsEqual', () => {
  const digest = sha256Hex('x');

  it('accepts equal digests', () => expect(hexDigestsEqual(digest, sha256Hex('x'))).toBe(true));

  it('refuses different digests', () =>
    expect(hexDigestsEqual(digest, sha256Hex('y'))).toBe(false));

  it('refuses malformed hex even when a lenient decoder would match', () => {
    expect(hexDigestsEqual(`${digest}zz`, `${digest}zz`)).toBe(false);
    expect(hexDigestsEqual('ABCD', 'ABCD')).toBe(false);
    expect(hexDigestsEqual('', '')).toBe(false);
  });
});

describe('secretsEqual', () => {
  it('compares values of different lengths without throwing', () => {
    expect(secretsEqual('a', 'a')).toBe(true);
    expect(secretsEqual('a', 'ab')).toBe(false);
  });
});
