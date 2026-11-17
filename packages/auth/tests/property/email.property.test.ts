// Properties of email normalisation. Two spellings of one address must land
// on one account, and no non-ASCII character may survive, because Unicode
// case folding maps distinct characters onto ASCII ones and would let two
// different addresses share an account.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { normalizeEmail } from '../../src/shared/email';
import { runs } from './runs';

const local = fc.stringMatching(/^[A-Za-z0-9._+-]{1,30}$/u);
const label = fc.stringMatching(/^[A-Za-z0-9-]{1,20}$/u);

const address = fc
  .tuple(
    local,
    fc.array(label, { minLength: 1, maxLength: 3 }),
    fc.stringMatching(/^[A-Za-z]{2,6}$/u),
  )
  .map(([l, labels, tld]) => `${l}@${[...labels, tld].join('.')}`);

/** An address with printable ASCII (some of it uppercase, `@`, `.`) spliced in. */
const noisy = fc.tuple(address, fc.string({ maxLength: 260 }), fc.nat()).map(([raw, extra, at]) => {
  const index = at % (raw.length + 1);

  return `${raw.slice(0, index)}${extra}${raw.slice(index)}`;
});

const asciiSpace = fc.string({ unit: fc.constantFrom(' ', '\t', '\n', '\r'), maxLength: 3 });

const nonAscii = fc
  .string({ unit: 'binary', minLength: 1, maxLength: 1 })
  .filter((c) => c.charCodeAt(0) > 0x7e);

/** Flips the case of the ASCII letters picked by the mask. */
function recase(value: string, mask: readonly boolean[]): string {
  return [...value]
    .map((c, i) =>
      mask[i % Math.max(1, mask.length)] === true ? c.toUpperCase() : c.toLowerCase(),
    )
    .join('');
}

describe('normalizeEmail', () => {
  it('is idempotent on arbitrary input', () => {
    fc.assert(
      fc.property(fc.oneof(address, noisy, fc.string({ unit: 'binary' })), (raw) => {
        const once = normalizeEmail(raw);

        expect(once === null ? null : normalizeEmail(once)).toBe(once);
      }),
      runs(),
    );
  });

  it('gives lowercase printable ASCII with one @, at most 254 characters', () => {
    fc.assert(
      fc.property(fc.oneof(address, noisy), (raw) => {
        const value = normalizeEmail(raw);

        fc.pre(value !== null);
        expect(value).toMatch(/^[\x21-\x40\x5b-\x7e]+$/u);
        expect(value.split('@')).toHaveLength(2);
        expect(value.length).toBeLessThanOrEqual(254);
      }),
      runs(),
    );
  });

  it('accepts every generated address and refuses it with any non-ASCII character inside', () => {
    fc.assert(
      fc.property(address, nonAscii, fc.nat(), (raw, c, at) => {
        const index = 1 + (at % (raw.length - 1));

        expect(normalizeEmail(raw)).not.toBeNull();
        expect(normalizeEmail(`${raw.slice(0, index)}${c}${raw.slice(index)}`)).toBeNull();
      }),
      runs(),
    );
  });

  it('normalises every case variant of an address to the same value', () => {
    fc.assert(
      fc.property(address, fc.array(fc.boolean(), { minLength: 1 }), (raw, mask) => {
        expect(normalizeEmail(recase(raw, mask))).toBe(normalizeEmail(raw.toLowerCase()));
        expect(normalizeEmail(raw)).toBe(raw.toLowerCase());
      }),
      runs(),
    );
  });

  it('ignores surrounding ASCII whitespace', () => {
    fc.assert(
      fc.property(address, asciiSpace, asciiSpace, (raw, before, after) => {
        expect(normalizeEmail(`${before}${raw}${after}`)).toBe(normalizeEmail(raw));
      }),
      runs(),
    );
  });

  it('refuses an address longer than 254 characters or with a local part over 64', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 65, max: 120 }),
        fc.integer({ min: 255, max: 400 }),
        (l, total) => {
          expect(normalizeEmail(`${'a'.repeat(l)}@example.com`)).toBeNull();
          expect(normalizeEmail(`a@${'b'.repeat(total - 6)}.com`)).toBeNull();
        },
      ),
      runs(),
    );
  });
});
