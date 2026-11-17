import { describe, expect, it } from 'vitest';

import {
  generateNumericCode,
  generateToken,
  isTokenShape,
  TOKEN_BYTES,
} from '../../src/crypto/random';

describe('generateToken', () => {
  it('mints 32 bytes as 64 lowercase hex characters', () => {
    const token = generateToken();

    expect(TOKEN_BYTES).toBe(32);
    expect(token).toMatch(/^[0-9a-f]{64}$/u);
    expect(isTokenShape(token)).toBe(true);
  });

  it('never repeats across a large sample', () => {
    const seen = new Set(Array.from({ length: 2000 }, () => generateToken()));

    expect(seen.size).toBe(2000);
  });
});

describe('isTokenShape', () => {
  it.each([
    '',
    '*',
    'A'.repeat(64),
    'a'.repeat(63),
    'a'.repeat(65),
    `${'a'.repeat(63)}\n`,
    42,
    null,
  ])('refuses %j', (value) => {
    expect(isTokenShape(value)).toBe(false);
  });
});

describe('generateNumericCode', () => {
  it('pads to the requested number of digits', () => {
    const zeros = (bytes: Uint8Array) => bytes.fill(0);

    expect(generateNumericCode(6, zeros)).toBe('000000');
    expect(generateNumericCode(8)).toMatch(/^\d{8}$/u);
  });

  it('rejects values above the largest multiple of the modulus instead of biasing low codes', () => {
    // First draw is 0xffffffff (above the limit for 6 digits), second is 7.
    const draws = [
      [0xff, 0xff, 0xff, 0xff],
      [0, 0, 0, 7],
    ];

    const source = (bytes: Uint8Array) => bytes.set(draws.shift() ?? [0, 0, 0, 0]);

    expect(generateNumericCode(6, source)).toBe('000007');
    expect(draws).toHaveLength(0);
  });

  it('rejects a draw exactly at the limit, the first value that would bias the codes', () => {
    // For 6 digits the limit is floor(2^32 / 10^6) * 10^6 = 4_294_000_000 (0xFFF1_3D80).
    const draws = [
      [0xff, 0xf1, 0x3d, 0x80],
      [0xff, 0xf1, 0x3d, 0x7f],
    ];

    const source = (bytes: Uint8Array) => bytes.set(draws.shift() ?? [0, 0, 0, 0]);

    expect(generateNumericCode(6, source)).toBe('999999');
    expect(draws).toHaveLength(0);
  });

  it('refuses digit counts outside 6 to 9', () => {
    expect(() => generateNumericCode(5)).toThrow('A numeric code has 6 to 9 digits');
    expect(() => generateNumericCode(5)).toThrow(RangeError);
    expect(() => generateNumericCode(10)).toThrow(RangeError);
  });

  it('is roughly uniform over the first digit', () => {
    const counts = new Array<number>(10).fill(0);

    for (let i = 0; i < 20_000; i++) {
      const first = Number(generateNumericCode(6)[0]);

      counts[first] = (counts[first] ?? 0) + 1;
    }

    for (const count of counts) expect(count).toBeGreaterThan(1500);
  });
});
