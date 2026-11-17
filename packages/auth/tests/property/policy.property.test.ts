// Properties of the password length policy. Counting UTF-16 units instead of
// NFC code points would make an emoji password "longer" than it is and a
// password typed on a phone (often NFD) a different length from the same one
// typed on a desktop, so the boundaries are tested with exactly those inputs.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { checkPasswordPolicy, type PasswordPolicy } from '../../src/password/policy';
import { runs } from './runs';

/**
 * Characters that count as one code point after NFC, written as they might
 * arrive: plain ASCII, BMP letters, astral characters (two UTF-16 units) and
 * NFD sequences that NFC composes into one code point.
 */
const unit = fc.constantFrom(
  'a',
  'Z',
  '7',
  ' ',
  'é', // é, precomposed
  'é', // é, decomposed: two code points before NFC
  'ṩ', // ṩ, precomposed
  'ṩ', // ṩ, decomposed: three code points before NFC
  '가', // 가, precomposed
  '가', // 가 as conjoining jamo: two code points before NFC
  '漢', // 漢
  '\u{1f600}', // 😀, astral
  '\u{1d49c}', // 𝒜, astral
);

/** A password of exactly `length` NFC code points. */
function password(length: number) {
  return fc.array(unit, { minLength: length, maxLength: length }).map((units) => units.join(''));
}

const policy = fc
  .tuple(fc.integer({ min: 1, max: 40 }), fc.integer({ min: 0, max: 40 }))
  .map(([minLength, spread]): PasswordPolicy => ({ minLength, maxLength: minLength + spread }));

describe('checkPasswordPolicy', () => {
  it('draws the boundaries exactly at minLength and maxLength, in NFC code points', () => {
    fc.assert(
      fc.property(
        policy.chain((p) =>
          fc.record({
            p: fc.constant(p),
            short: password(p.minLength - 1),
            min: password(p.minLength),
            max: password(p.maxLength),
            long: password(p.maxLength + 1),
          }),
        ),
        ({ p, short, min, max, long }) => {
          expect(checkPasswordPolicy(short, p)).toBe('too_short');
          expect(checkPasswordPolicy(min, p)).toBe('ok');
          expect(checkPasswordPolicy(max, p)).toBe('ok');
          expect(checkPasswordPolicy(long, p)).toBe('too_long');
        },
      ),
      runs(),
    );
  });

  it('gives an NFD password the verdict of its NFC length, not of its longer NFD length', () => {
    const sized = fc
      .integer({ min: 0, max: 90 })
      .chain((length) => fc.tuple(fc.constant(length), password(length)));

    fc.assert(
      fc.property(policy, sized, (p, [length, value]) => {
        const verdict =
          length < p.minLength ? 'too_short' : length > p.maxLength ? 'too_long' : 'ok';

        expect([...value.normalize('NFC')]).toHaveLength(length);
        expect(checkPasswordPolicy(value.normalize('NFD'), p)).toBe(verdict);
        expect(checkPasswordPolicy(value, p)).toBe(verdict);
      }),
      runs(),
    );
  });

  it('agrees with a code-point count of the NFC form on arbitrary strings', () => {
    fc.assert(
      fc.property(policy, fc.string({ unit: 'binary', maxLength: 90 }), (p, value) => {
        const length = [...value.normalize('NFC')].length;

        const verdict =
          length < p.minLength ? 'too_short' : length > p.maxLength ? 'too_long' : 'ok';

        expect(checkPasswordPolicy(value, p)).toBe(verdict);
      }),
      runs(),
    );
  });
});
