import { describe, expect, it } from 'vitest';

import {
  generateRecoveryCode,
  generateRecoveryCodes,
  normalizeRecoveryCode,
} from '../../src/plugins/two-factor/recovery-codes';
import {
  encodeTotpSecret,
  generateTotpSecret,
  matchTotp,
  timeStep,
  totpCode,
  totpUri,
} from '../../src/plugins/two-factor/totp';

const RFC_SECRET = new TextEncoder().encode('12345678901234567890');

/** RFC 6238 appendix B, SHA-1 column: Unix time in seconds and the 8-digit code. */
const RFC_6238_SHA1: ReadonlyArray<readonly [number, string]> = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

/** RFC 4226 appendix D: HOTP values for counters 0 to 9 (6 digits). */
const RFC_4226 = [
  '755224',
  '287082',
  '359152',
  '969429',
  '338314',
  '254676',
  '287922',
  '162583',
  '399871',
  '520489',
];

describe('TOTP', () => {
  it('passes the RFC 6238 test vectors (SHA-1)', () => {
    for (const [seconds, code] of RFC_6238_SHA1)
      expect(totpCode(RFC_SECRET, timeStep(seconds * 1000), 8)).toBe(code);
  });

  it('passes the RFC 4226 HOTP vectors it is built on', () => {
    RFC_4226.forEach((code, counter) => expect(totpCode(RFC_SECRET, counter)).toBe(code));
  });

  it('uses 30-second steps', () => {
    expect(timeStep(0)).toBe(0);
    expect(timeStep(29_999)).toBe(0);
    expect(timeStep(30_000)).toBe(1);
    expect(timeStep(59_000)).toBe(1);
  });

  it('matches within one step either side and returns the step', () => {
    const now = 1_700_000_000_000;
    const step = timeStep(now);

    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step), now)).toBe(step);
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 1), now)).toBe(step - 1);
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 1), now)).toBe(step + 1);
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 2), now)).toBeNull();
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 2), now)).toBeNull();
  });

  it('refuses malformed codes', () => {
    const now = 1_700_000_000_000;
    const code = totpCode(RFC_SECRET, timeStep(now));

    for (const bad of [
      '',
      '12345',
      '1234567',
      'abcdef',
      `${code}0`,
      `+${code.slice(1)}`,
      null,
      123456,
      undefined,
    ])
      expect(matchTotp(RFC_SECRET, bad, now)).toBeNull();

    expect(matchTotp(RFC_SECRET, `${code.slice(0, 3)} ${code.slice(3)}`, now)).toBe(timeStep(now));
  });

  it('generates 160-bit secrets from the random source', () => {
    let calls = 0;

    const secret = generateTotpSecret((bytes) => {
      calls++;
      bytes.fill(0xab);
    });

    expect(secret).toHaveLength(20);
    expect(calls).toBe(1);
    expect(encodeTotpSecret(secret)).toBe('VOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5L');
  });

  it('percent-encodes issuer and account in the URI, with %20 for a space', () => {
    expect(totpUri('Acme Corp & Co', 'a+b c@example.com', RFC_SECRET)).toBe(
      'otpauth://totp/Acme%20Corp%20%26%20Co:a%2Bb%20c%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme%20Corp%20%26%20Co&algorithm=SHA1&digits=6&period=30',
    );
  });
});

describe('recovery codes', () => {
  it('generates ten codes of ten base32 characters, 50 bits each', () => {
    const codes = generateRecoveryCodes(globalThis.crypto.getRandomValues.bind(globalThis.crypto));

    expect(codes).toHaveLength(10);

    for (const code of codes)
      expect(code).toMatch(/^[0-9a-hjkmnp-tv-z]{5}-[0-9a-hjkmnp-tv-z]{5}$/u);
  });

  it('maps every byte value onto the alphabet uniformly', () => {
    const seen = new Set<string>();

    for (let b = 0; b < 256; b++) {
      const code = generateRecoveryCode((bytes) => bytes.fill(b));

      seen.add(code[0] ?? '');
      expect(code).toBe(`${code[0]?.repeat(5)}-${code[0]?.repeat(5)}`);
    }

    expect([...seen].sort().join('')).toBe('0123456789abcdefghjkmnpqrstvwxyz');
  });

  it('normalises case, spaces and dashes, and refuses anything else', () => {
    expect(normalizeRecoveryCode('ABCDE-FGHJK')).toBe('abcdefghjk');
    expect(normalizeRecoveryCode(' abcde fghjk ')).toBe('abcdefghjk');
    expect(normalizeRecoveryCode('abcdefghjk')).toBe('abcdefghjk');

    for (const bad of [
      'abcde-fghj',
      'abcde-fghjkm',
      'abcde-fghjl', // l is not in the alphabet
      'abcde-fghji',
      'abcde-fghjo',
      'abcde-fghju',
      'abcde_fghjk',
      'abcde-fghjK', // Kelvin sign: lowers to k outside ASCII
      `abcde-fghjk${' '.repeat(30)}`,
      42,
      null,
    ])
      expect(normalizeRecoveryCode(bad)).toBeNull();
  });
});
