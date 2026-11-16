import { describe, expect, it } from 'vitest';

import { toMilliseconds, toSeconds } from '../../src/shared/duration';

describe('durations', () => {
  it('reads bare numbers as seconds', () => expect(toMilliseconds(90)).toBe(90_000));

  it.each([
    ['500ms', 500],
    ['15m', 900_000],
    ['1h', 3_600_000],
    ['30d', 2_592_000_000],
    ['1.5s', 1500],
  ] as const)('parses %s', (input, ms) => expect(toMilliseconds(input)).toBe(ms));

  it('rounds seconds up so a TTL is never shorter than asked', () =>
    expect(toSeconds('1500ms')).toBe(2));

  it('refuses garbage and negatives', () => {
    expect(() => toMilliseconds('10x' as never)).toThrow(TypeError);
    expect(() => toMilliseconds(-1)).toThrow(TypeError);
  });
});
