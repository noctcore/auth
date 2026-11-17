// Properties of the trusted-device token, the cookie that lets a correct
// password through an account lock. A token that verified for another user,
// an old epoch, another key, outside its age window or in a second spelling
// would turn the lockout bypass into a way around the lockout itself.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { hmacSha256Hex } from '../../src/crypto/hash';
import {
  createDeviceToken,
  verifyDeviceToken,
  type DeviceCheck,
  type DeviceClaims,
} from '../../src/throttle/device-token';
import { runs } from './runs';

const SKEW_MS = 60_000;
const DAY_MS = 86_400_000;

const key = fc.uint8Array({ minLength: 32, maxLength: 32 });
const deviceId = fc.uint8Array({ minLength: 16, maxLength: 16 });
const userId = fc.string({ unit: 'binary', minLength: 1, maxLength: 40 });
// Issue times up to the year 2500 and epochs a counter can reach: far below
// 2^53, so every decimal field has exactly one spelling.
const issuedAt = fc.integer({ min: 0, max: 16_725_225_600_000 });
const epoch = fc.integer({ min: 0, max: 1_000_000_000 });
const maxAgeMs = fc.integer({ min: 1, max: 400 * DAY_MS });

interface Case {
  readonly key: Uint8Array;
  readonly claims: DeviceClaims;
  readonly maxAgeMs: number;
  readonly token: string;
  readonly id: string;
  /** A check that accepts the token: same user and epoch, inside the age window. */
  readonly check: DeviceCheck;
}

const issued = fc
  .record({
    key,
    deviceId,
    userId,
    issuedAt,
    epoch,
    maxAgeMs,
    // Where `now` falls in the accepted window [issuedAt - skew, issuedAt + maxAge].
    offset: fc.double({ min: 0, max: 1, noNaN: true }),
  })
  .map((input): Case => {
    const claims = { userId: input.userId, epoch: input.epoch, issuedAt: input.issuedAt };
    const span = SKEW_MS + input.maxAgeMs;
    const now = input.issuedAt - SKEW_MS + Math.round(input.offset * span);
    const token = createDeviceToken(input.key, claims, (bytes) => bytes.set(input.deviceId));

    return {
      key: input.key,
      claims,
      maxAgeMs: input.maxAgeMs,
      token,
      id: Buffer.from(input.deviceId).toString('hex'),
      check: { userId: claims.userId, epoch: claims.epoch, now, maxAgeMs: input.maxAgeMs },
    };
  });

function fields(token: string): [string, string, string, string] {
  const [id = '', at = '', ep = '', mac = ''] = token.split('.');

  return [id, at, ep, mac];
}

describe('verifyDeviceToken', () => {
  it('accepts a token for its own claims anywhere inside the age window', () => {
    fc.assert(
      fc.property(issued, (c) => {
        expect(verifyDeviceToken(c.key, c.token, c.check)).toBe(c.id);
      }),
      runs(),
    );
  });

  it('accepts at both edges of the window and refuses one millisecond outside', () => {
    fc.assert(
      fc.property(issued, (c) => {
        const at = c.claims.issuedAt;
        const verify = (now: number) => verifyDeviceToken(c.key, c.token, { ...c.check, now });

        expect(verify(at - SKEW_MS)).toBe(c.id);
        expect(verify(at + c.maxAgeMs)).toBe(c.id);
        expect(verify(at - SKEW_MS - 1)).toBeNull();
        expect(verify(at + c.maxAgeMs + 1)).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses a token beyond its max age or more than a minute in the future', () => {
    fc.assert(
      fc.property(issued, fc.integer({ min: 1, max: 1000 * DAY_MS }), (c, beyond) => {
        const at = c.claims.issuedAt;

        expect(
          verifyDeviceToken(c.key, c.token, { ...c.check, now: at + c.maxAgeMs + beyond }),
        ).toBeNull();

        expect(
          verifyDeviceToken(c.key, c.token, { ...c.check, now: at - SKEW_MS - beyond }),
        ).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses a token for another user, another epoch or under another key', () => {
    fc.assert(
      fc.property(issued, userId, epoch, key, (c, otherUser, otherEpoch, otherKey) => {
        fc.pre(otherUser !== c.claims.userId);
        fc.pre(otherEpoch !== c.claims.epoch);
        fc.pre(Buffer.compare(otherKey, c.key) !== 0);

        expect(verifyDeviceToken(c.key, c.token, { ...c.check, userId: otherUser })).toBeNull();
        expect(verifyDeviceToken(c.key, c.token, { ...c.check, epoch: otherEpoch })).toBeNull();
        expect(verifyDeviceToken(otherKey, c.token, c.check)).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses a token truncated at any position or extended by anything', () => {
    fc.assert(
      fc.property(issued, fc.nat(), fc.string({ minLength: 1 }), (c, at, extra) => {
        const keep = at % c.token.length;

        expect(verifyDeviceToken(c.key, c.token.slice(0, keep), c.check)).toBeNull();
        expect(verifyDeviceToken(c.key, `${c.token}${extra}`, c.check)).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses a token with any single character changed', () => {
    const replacement = fc.oneof(
      fc.constantFrom(...'0123456789abcdefABCDEF.'),
      fc.string({ unit: 'binary', minLength: 1, maxLength: 1 }),
    );

    fc.assert(
      fc.property(issued, fc.nat(), replacement, (c, at, char) => {
        const index = at % c.token.length;

        fc.pre(c.token.charAt(index) !== char);

        const changed = `${c.token.slice(0, index)}${char}${c.token.slice(index + 1)}`;

        expect(verifyDeviceToken(c.key, changed, c.check)).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses a decimal field padded with leading zeros', () => {
    fc.assert(
      fc.property(issued, fc.integer({ min: 1, max: 3 }), fc.boolean(), (c, zeros, padIssued) => {
        const [id, at, ep, mac] = fields(c.token);
        const pad = '0'.repeat(zeros);

        const padded = padIssued
          ? `${id}.${pad}${at}.${ep}.${mac}`
          : `${id}.${at}.${pad}${ep}.${mac}`;

        expect(verifyDeviceToken(c.key, padded, c.check)).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses a token with two of its fields swapped', () => {
    const pairs: readonly (readonly [number, number])[] = [
      [0, 1],
      [0, 2],
      [0, 3],
      [1, 2],
      [1, 3],
      [2, 3],
    ];

    fc.assert(
      fc.property(issued, fc.constantFrom(...pairs), (c, [i, j]) => {
        const parts = fields(c.token);

        fc.pre(parts[i] !== parts[j]);

        const swapped = [...parts];

        swapped[i] = parts[j] ?? '';
        swapped[j] = parts[i] ?? '';

        // Swapping issue time and epoch keeps the shape; the check must still
        // see whichever epoch the token now claims.
        expect(verifyDeviceToken(c.key, swapped.join('.'), c.check)).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses arbitrary strings and non-strings', () => {
    fc.assert(
      fc.property(key, fc.oneof(fc.string(), fc.anything()), userId, (k, token, user) => {
        const check = { userId: user, epoch: 0, now: Date.now(), maxAgeMs: DAY_MS };

        expect(verifyDeviceToken(k, token, check)).toBeNull();
      }),
      runs(),
    );
  });

  it('refuses issue times past 2^53 for any realistic clock, the only place two spellings meet', () => {
    // A 16-digit field can exceed 2^53, where two spellings parse to one
    // number and so share one MAC. The age window refuses those tokens while
    // `now` is below about the year 287000; only a clock that far ahead would
    // accept the second spelling.
    fc.assert(
      fc.property(
        key,
        deviceId,
        userId,
        fc.bigInt({ min: 2n ** 53n, max: 10n ** 16n - 1n }),
        (k, id, user, at) => {
          const hexId = Buffer.from(id).toString('hex');
          const parsed = Number(at);
          const mac = hmacSha256Hex(k, `device:${user.length}:${user}:0:${parsed}:${hexId}`);
          const token = `${hexId}.${at}.0.${mac}`;
          const check = { userId: user, epoch: 0, now: 16_725_225_600_000, maxAgeMs: DAY_MS };

          expect(verifyDeviceToken(k, token, check)).toBeNull();
          expect(verifyDeviceToken(k, token, { ...check, now: parsed })).toBe(hexId);
        },
      ),
      runs(),
    );
  });
});
