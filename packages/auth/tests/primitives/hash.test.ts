import { timingSafeEqual } from 'node:crypto';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  bytesEqualWith,
  findNativeTimingSafeEqual,
  hexDigestsEqual,
  hmacSha256Hex,
  secretsEqual,
  sha256Hex,
} from '../../src/crypto/hash';

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

describe('findNativeTimingSafeEqual', () => {
  it("finds node:crypto's timingSafeEqual on Node", () =>
    expect(findNativeTimingSafeEqual()).toBe(timingSafeEqual));

  it('finds nothing where the runtime has no Node built-ins, without throwing', () => {
    const throwing = {
      process: {
        getBuiltinModule: () => {
          throw new Error('not here');
        },
      },
    };

    const hosts = [
      {},
      { process: {} },
      { process: { getBuiltinModule: () => undefined } },
      { process: { getBuiltinModule: () => ({}) } },
      { process: { getBuiltinModule: () => ({ timingSafeEqual: 'no' }) } },
      throwing,
      null,
    ];

    expect(hosts.map((host) => findNativeTimingSafeEqual(host))).toEqual(
      hosts.map(() => undefined),
    );
  });
});

const PATHS = [
  ['native timingSafeEqual', bytesEqualWith(timingSafeEqual)],
  ['JavaScript fallback', bytesEqualWith(undefined)],
] as const;

describe.each(PATHS)('bytesEqualWith (%s)', (_, equal) => {
  const bytes = (...values: number[]) => Uint8Array.from(values);

  it('accepts equal arrays, including empty ones', () => {
    expect(equal(bytes(1, 2, 3), bytes(1, 2, 3))).toBe(true);
    expect(equal(bytes(), bytes())).toBe(true);
  });

  it('refuses arrays that differ in any byte', () => {
    expect(equal(bytes(1, 2, 3), bytes(0, 2, 3))).toBe(false);
    expect(equal(bytes(1, 2, 3), bytes(1, 2, 4))).toBe(false);
  });

  it('refuses arrays of different lengths without throwing', () => {
    expect(equal(bytes(1, 2), bytes(1, 2, 3))).toBe(false);
    expect(equal(bytes(1, 2, 3), bytes(1, 2))).toBe(false);
    expect(equal(bytes(), bytes(0))).toBe(false);
  });

  it('agrees with a byte-by-byte comparison on any input', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 40 }), fc.uint8Array({ maxLength: 40 }), (a, b) => {
        const same = a.length === b.length && a.every((value, i) => value === b[i]);

        expect(equal(a, b)).toBe(same);
        expect(equal(a, Uint8Array.from(a))).toBe(true);
      }),
    );
  });
});
