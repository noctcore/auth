// Properties of the duration parser. A TTL read as milliseconds in one place
// and seconds in another, or a garbage value read as zero or Infinity, would
// give sessions and codes lifetimes nobody configured.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { toMilliseconds, toSeconds, type Duration } from '../../src/shared/duration';
import { runs } from './runs';

const UNIT_MS = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const;
const unit = fc.constantFrom(...(Object.keys(UNIT_MS) as (keyof typeof UNIT_MS)[]));

/** A plain decimal as the pattern accepts it: digits, optionally a fraction. */
const decimal = fc
  .tuple(
    fc.nat({ max: 10_000_000 }),
    fc.option(fc.stringMatching(/^\d{1,4}$/u), { nil: undefined }),
  )
  .map(([whole, fraction]) => (fraction === undefined ? `${whole}` : `${whole}.${fraction}`));

describe('toMilliseconds', () => {
  it('reads a bare number as seconds, the same as the string with the s unit', () => {
    fc.assert(
      fc.property(decimal, (value) => {
        expect(toMilliseconds(Number(value))).toBe(toMilliseconds(`${value}s` as Duration));
      }),
      runs(),
    );
  });

  it('agrees across units for whole amounts', () => {
    fc.assert(
      fc.property(fc.nat({ max: 100_000 }), (n) => {
        const ms = n * 1000;

        expect(toMilliseconds(n)).toBe(ms);
        expect(toMilliseconds(`${n}s`)).toBe(ms);
        expect(toMilliseconds(`${ms}ms`)).toBe(ms);
        expect(toMilliseconds(`${n}m`)).toBe(n * 60_000);
        expect(toMilliseconds(`${n * 60}m`)).toBe(toMilliseconds(`${n}h`));
        expect(toMilliseconds(`${n * 24}h`)).toBe(toMilliseconds(`${n}d`));
      }),
      runs(),
    );
  });

  it('rounds to the nearest millisecond, never more than half a millisecond off', () => {
    fc.assert(
      fc.property(decimal, unit, (value, u) => {
        const exact = Number(value) * UNIT_MS[u];
        const ms = toMilliseconds(`${value}${u}` as Duration);

        expect(Number.isInteger(ms)).toBe(true);
        expect(Math.abs(ms - exact)).toBeLessThanOrEqual(0.5);
      }),
      runs(),
    );
  });

  it('refuses garbage: other units, signs, exponents, whitespace, NaN and Infinity', () => {
    const garbage = fc
      .string({ unit: 'binary', maxLength: 12 })
      .filter((value) => !/^\d+(?:\.\d+)?(?:ms|s|m|h|d)$/u.test(value));

    const badNumber = fc.oneof(
      fc.double({ max: -Number.MIN_VALUE }),
      fc.constantFrom(Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY),
      fc.double({ min: 1e306, noNaN: true }),
    );

    fc.assert(
      fc.property(garbage, badNumber, (text, number) => {
        expect(() => toMilliseconds(text as Duration)).toThrow(TypeError);
        expect(() => toMilliseconds(number)).toThrow(TypeError);
      }),
      runs(),
    );
  });

  it('either returns a finite whole number or throws, for any value the pattern accepts', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^\d{1,400}$/u), unit, (digits, u) => {
        const exact = Number(digits) * UNIT_MS[u];
        let outcome: unknown;

        try {
          outcome = toMilliseconds(`${digits}${u}` as Duration);
        } catch (error) {
          outcome = error instanceof TypeError ? 'refused' : error;
        }

        expect(outcome).toBe(Number.isFinite(exact) ? Math.round(exact) : 'refused');
      }),
      runs(),
    );
  });
});

describe('toSeconds', () => {
  it('rounds up from the parsed milliseconds, so it never undercuts toMilliseconds', () => {
    fc.assert(
      fc.property(decimal, unit, (value, u) => {
        const duration = `${value}${u}` as Duration;
        const seconds = toSeconds(duration);

        expect(Number.isInteger(seconds)).toBe(true);
        expect(seconds * 1000).toBeGreaterThanOrEqual(toMilliseconds(duration));
        expect((seconds - 1) * 1000).toBeLessThan(toMilliseconds(duration));
      }),
      runs(),
    );
  });
});
