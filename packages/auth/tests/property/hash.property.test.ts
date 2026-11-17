// Properties of the digest comparisons and the token shape check. A lenient
// hex comparison would let two malformed strings map to the same bytes, and a
// loose token pre-filter would let junk reach the store keys, so both are
// tested on arbitrary input, not only on the values the package mints.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { hexDigestsEqual, secretsEqual } from '../../src/crypto/hash';
import {
  generateNumericCode,
  generateToken,
  isTokenShape,
  TOKEN_BYTES,
  type RandomSource,
} from '../../src/crypto/random';
import { runs } from './runs';

const HEX_DIGITS = '0123456789abcdef';

/** Well-formed lowercase hex: an even number of digits, at least two. */
const hexDigest = fc
  .uint8Array({ minLength: 1, maxLength: 64 })
  .map((bytes) => Buffer.from(bytes).toString('hex'));

/** A RandomSource that replays the given bytes, so a token is a function of them. */
function replay(bytes: Uint8Array): RandomSource {
  return (target) => {
    target.set(bytes.subarray(0, target.length));
  };
}

const token = fc
  .uint8Array({ minLength: TOKEN_BYTES, maxLength: TOKEN_BYTES })
  .map((bytes) => generateToken(replay(bytes)));

/** Any single character that is not a lowercase hex digit. */
const nonHexChar = fc
  .string({ unit: 'binary', minLength: 1, maxLength: 1 })
  .filter((c) => !HEX_DIGITS.includes(c));

describe('hexDigestsEqual', () => {
  it('is reflexive on well-formed lowercase hex', () => {
    fc.assert(
      fc.property(hexDigest, (digest) => {
        expect(hexDigestsEqual(digest, digest)).toBe(true);
      }),
      runs(),
    );
  });

  it('refuses any two different digests and is symmetric', () => {
    fc.assert(
      fc.property(hexDigest, hexDigest, (a, b) => {
        fc.pre(a !== b);
        expect(hexDigestsEqual(a, b)).toBe(false);
        expect(hexDigestsEqual(b, a)).toBe(false);
      }),
      runs(),
    );
  });

  it('refuses a digest that differs in one digit', () => {
    fc.assert(
      fc.property(hexDigest, fc.nat(), fc.integer({ min: 1, max: 15 }), (digest, at, shift) => {
        const index = at % digest.length;
        const digit = HEX_DIGITS.indexOf(digest.charAt(index));
        const other = HEX_DIGITS.charAt((digit + shift) % 16);
        const changed = `${digest.slice(0, index)}${other}${digest.slice(index + 1)}`;

        expect(hexDigestsEqual(digest, changed)).toBe(false);
        expect(hexDigestsEqual(changed, digest)).toBe(false);
      }),
      runs(),
    );
  });

  it('refuses uppercase, odd-length, non-hex and empty input, even against itself', () => {
    const uppercase = hexDigest
      .filter((digest) => /[a-f]/u.test(digest))
      .map((digest) => digest.toUpperCase());

    const oddLength = hexDigest.map((digest) => digest.slice(1));

    const nonHex = fc
      .tuple(hexDigest, nonHexChar, fc.nat())
      .map(([digest, c, at]) => {
        const index = at % (digest.length + 1);

        return `${digest.slice(0, index)}${c}${digest.slice(index)}`;
      })
      .filter((value) => value.length % 2 === 0);

    const malformed = fc.oneof(uppercase, oddLength, nonHex, fc.constant(''));

    fc.assert(
      fc.property(malformed, hexDigest, (bad, good) => {
        expect(hexDigestsEqual(bad, bad)).toBe(false);
        expect(hexDigestsEqual(bad, good)).toBe(false);
        expect(hexDigestsEqual(good, bad)).toBe(false);
      }),
      runs(),
    );
  });

  it('agrees with string equality on arbitrary strings that are well-formed hex', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        const wellFormed = (value: string) => /^(?:[0-9a-f]{2})+$/u.test(value);

        expect(hexDigestsEqual(a, b)).toBe(wellFormed(a) && wellFormed(b) && a === b);
      }),
      runs(),
    );
  });
});

describe('secretsEqual', () => {
  it('equals === on arbitrary strings', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'binary' }), fc.string({ unit: 'binary' }), (a, b) => {
        expect(secretsEqual(a, b)).toBe(a === b);
        expect(secretsEqual(a, a)).toBe(true);
      }),
      runs(),
    );
  });

  it('refuses a secret that differs in one character', () => {
    fc.assert(
      fc.property(
        fc.string({ unit: 'grapheme-ascii', minLength: 1 }),
        fc.nat(),
        fc.string({ unit: 'grapheme-ascii', minLength: 1, maxLength: 1 }),
        (secret, at, c) => {
          const index = at % secret.length;

          fc.pre(secret.charAt(index) !== c);

          const changed = `${secret.slice(0, index)}${c}${secret.slice(index + 1)}`;

          expect(secretsEqual(secret, changed)).toBe(false);
        },
      ),
      runs(),
    );
  });
});

describe('isTokenShape and generateToken', () => {
  it('accepts every generated token', () => {
    fc.assert(
      fc.property(token, (value) => {
        expect(value).toHaveLength(TOKEN_BYTES * 2);
        expect(isTokenShape(value)).toBe(true);
      }),
      runs(),
    );
  });

  it('refuses a token with any one character changed to a non-hex character', () => {
    fc.assert(
      fc.property(token, fc.nat(), nonHexChar, (value, at, c) => {
        const index = at % value.length;
        const changed = `${value.slice(0, index)}${c}${value.slice(index + 1)}`;

        expect(isTokenShape(changed)).toBe(false);
      }),
      runs(),
    );
  });

  it('refuses a truncated or extended token', () => {
    fc.assert(
      fc.property(
        token,
        fc.integer({ min: 0, max: TOKEN_BYTES * 2 - 1 }),
        fc.string({ unit: 'binary', minLength: 1 }),
        (value, keep, extra) => {
          expect(isTokenShape(value.slice(0, keep))).toBe(false);
          expect(isTokenShape(`${value}${extra}`)).toBe(false);
          expect(isTokenShape(`${extra}${value}`)).toBe(false);
        },
      ),
      runs(),
    );
  });

  it('refuses every value that is not 64 lowercase hex digits', () => {
    fc.assert(
      fc.property(fc.anything(), (value) => {
        const shaped = typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);

        expect(isTokenShape(value)).toBe(shaped);
      }),
      runs(),
    );
  });
});

describe('generateNumericCode', () => {
  /**
   * A RandomSource that replays 32-bit words big-endian, cycling. The last
   * word is 0, which every modulus accepts, so rejection sampling ends.
   */
  function words(values: readonly number[]): RandomSource {
    const all = [...values, 0];
    let next = 0;

    return (target) => {
      const view = new DataView(target.buffer, target.byteOffset, target.byteLength);

      view.setUint32(0, all[next % all.length] ?? 0);
      next += 1;
    };
  }

  it('always gives exactly `digits` decimal digits, the first accepted word mod 10^digits', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 6, max: 9 }),
        fc.array(fc.nat({ max: 0xffff_ffff }), { maxLength: 8 }),
        (digits, values) => {
          const code = generateNumericCode(digits, words(values));
          const modulus = 10 ** digits;
          const limit = Math.floor(0x1_0000_0000 / modulus) * modulus;
          const accepted = [...values, 0].find((value) => value < limit) ?? 0;

          expect(code).toMatch(new RegExp(`^\\d{${digits}}$`, 'u'));
          expect(Number(code)).toBe(accepted % modulus);
        },
      ),
      runs(),
    );
  });

  it('refuses a digit count outside 6 to 9', () => {
    const outside = fc.oneof(
      fc.integer({ max: 5 }),
      fc.integer({ min: 10 }),
      fc.double().filter((value) => !Number.isInteger(value)),
    );

    fc.assert(
      fc.property(outside, (digits) => {
        expect(() => generateNumericCode(digits, words([]))).toThrow(RangeError);
      }),
      runs(),
    );
  });
});
