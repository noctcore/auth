// Properties every email policy keeps. Idempotence above all: a stored address
// is normalised again each time it is compared, so a policy whose output is
// not its own fixed point would stop matching the rows it wrote. The unicode
// policy must also give every case and every composition of an address one
// spelling, and keep nothing invisible.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  resolveEmailNormalizer,
  type EmailNormalizer,
  type EmailPolicy,
} from '../../src/shared/email';
import { runs } from './runs';

const quiet = () => undefined;

const POLICIES: ReadonlyArray<EmailPolicy> = ['standard', 'ascii', 'unicode'];

// A custom normaliser of the kind an app might bring: NFC and lowercase.
const nfcLower: EmailNormalizer = (email) => {
  const value = email.trim().normalize('NFC').toLowerCase().normalize('NFC');

  return /^[^\s,;:<>()"\\[\]@]+@[^\s,;:<>()"\\[\]@]+$/u.test(value) &&
    value.normalize('NFC').toLowerCase().normalize('NFC') === value
    ? value
    : null;
};

const codePoints = (...points: number[]) => points.map((c) => String.fromCodePoint(c));

const NEUTRAL = '0123456789._+-'.split('');
// Combining marks, so the same letter arrives composed and decomposed.
const MARKS = codePoints(0x301, 0x308, 0x307);

// One alphabet per address, so the unicode policy's single-script rule
// accepts most of them; the ASCII one feeds the standard and ascii policies.
const ALPHABETS: ReadonlyArray<readonly string[]> = [
  [...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''), ...NEUTRAL],
  [
    ...'abcdeiosuzABCDEISZ'.split(''),
    ...codePoints(0xe9, 0xc9, 0xfc, 0xdc, 0xdf, 0x1e9e, 0x130),
    ...MARKS,
    ...NEUTRAL,
  ],
  [...codePoints(0x3b1, 0x3b2, 0x391, 0x392, 0x3c3, 0x3a3, 0x3c2), ...MARKS, ...NEUTRAL],
  [...codePoints(0x430, 0x431, 0x410, 0x411, 0x439, 0x419, 0x451), ...MARKS, ...NEUTRAL],
  [...codePoints(0x5c71, 0x7530, 0x3042, 0x30a2), ...'abcXYZ'.split(''), ...NEUTRAL],
];

const address = fc.constantFrom(...ALPHABETS).chain((alphabet) => {
  const part = fc.string({ unit: fc.constantFrom(...alphabet), minLength: 1, maxLength: 20 });

  return fc
    .tuple(part, fc.array(part, { minLength: 1, maxLength: 3 }), part)
    .map(([local, labels, tld]) => `${local}@${[...labels, tld].join('.')}`);
});

const anything = fc.oneof(
  { arbitrary: address, weight: 4 },
  fc.string({ unit: 'grapheme', maxLength: 60 }),
  fc.string({ unit: 'binary', maxLength: 60 }),
);

describe('every email policy', () => {
  it.each([...POLICIES, 'custom'] as const)('%s is idempotent on arbitrary input', (name) => {
    const normalize = resolveEmailNormalizer(name === 'custom' ? nfcLower : name, quiet);

    fc.assert(
      fc.property(anything, (raw) => {
        const once = normalize(raw);

        expect(once.ok ? normalize(once.email) : once).toEqual(once);
      }),
      runs(),
    );
  });
});

describe('the unicode policy', () => {
  const normalize = resolveEmailNormalizer('unicode', quiet);

  it('gives composed, decomposed and recased input one spelling', () => {
    fc.assert(
      fc.property(address, (raw) => {
        const once = normalize(raw);

        fc.pre(once.ok);

        // Uppercases every letter that lowercases back to itself (not the
        // sharp s, which becomes SS, nor the final sigma).
        const upper = [...once.email]
          .map((c) => (c.toUpperCase().toLowerCase() === c ? c.toUpperCase() : c))
          .join('');

        for (const variant of [
          raw.normalize('NFD'),
          raw.normalize('NFC'),
          upper,
          upper.normalize('NFD'),
        ])
          expect(normalize(variant)).toEqual(once);
      }),
      runs(),
    );
  });

  it('never keeps a control, format, separator or compatibility character', () => {
    fc.assert(
      fc.property(anything, (raw) => {
        const once = normalize(raw);

        fc.pre(once.ok);
        expect(once.email).not.toMatch(/[\p{Cc}\p{Cf}\p{Z}\p{Default_Ignorable_Code_Point}]/u);
        expect(once.email.normalize('NFKC')).toBe(once.email);
        expect(once.email.split('@')).toHaveLength(2);
      }),
      runs(),
    );
  });
});
