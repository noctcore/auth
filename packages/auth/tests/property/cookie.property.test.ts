// Properties of the cookie writer and reader. A value that does not survive
// the round trip logs people out (or worse, reads as another token), a
// parser that throws on a hostile header is a denial of service, and a
// later duplicate that overrides the first is how a tossed cookie wins.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  createBlankSessionCookie,
  createSessionCookie,
  deviceCookie,
  parseCookieHeader,
  serializeCookie,
  type SameSite,
  type SessionCookieConfig,
} from '../../src/http/cookie';
import { runs } from './runs';

const baseName = fc.stringMatching(/^[A-Za-z0-9_-]{1,20}$/u);

// Well-formed Unicode, including `;`, `=`, spaces and astral characters.
// A lone surrogate cannot be percent-encoded, so it is left out here.
const value = fc.oneof(
  fc.string({ unit: 'grapheme', maxLength: 40 }),
  fc.string({ unit: fc.constantFrom(';', '=', ' ', ',', '%', '"', 'a', 'é', '\u{1f600}') }),
);

const sameSite = fc.constantFrom<SameSite>('lax', 'strict', 'none');

const config = fc
  .record({ name: baseName, secure: fc.boolean(), sameSite })
  .map((c): SessionCookieConfig =>
    c.sameSite === 'none'
      ? { ...c, secure: true }
      : { name: c.name, secure: c.secure, sameSite: c.sameSite },
  );

/** Every cookie the package writes, for one config. */
const spec = fc
  .tuple(config, value, fc.boolean(), fc.integer({ min: 0, max: 400 * 86_400 }), fc.nat(3))
  .map(([c, v, persistent, seconds, kind]) => {
    const now = 1_700_000_000_000;

    if (kind === 0) return createBlankSessionCookie(c);
    if (kind === 1) return deviceCookie(c, v, seconds);

    return createSessionCookie(c, v, { expiresAt: now + seconds * 1000, persistent, now });
  });

describe('serializeCookie and parseCookieHeader', () => {
  it('round-trips any well-formed value through name=value', () => {
    fc.assert(
      fc.property(spec, (cookie) => {
        const pair = serializeCookie(cookie).split('; ')[0] ?? '';

        expect(parseCookieHeader(pair).get(cookie.name)).toBe(cookie.value);
        expect(parseCookieHeader(`other=1; ${pair}; last=2`).get(cookie.name)).toBe(cookie.value);
      }),
      runs(),
    );
  });

  it('always writes HttpOnly and Path=/, and Secure whenever the name has the __Host- prefix', () => {
    fc.assert(
      fc.property(spec, (cookie) => {
        const attributes = serializeCookie(cookie).split('; ').slice(1);

        expect(attributes).toContain('HttpOnly');
        expect(attributes).toContain('Path=/');
        expect(attributes.includes('Secure')).toBe(cookie.name.startsWith('__Host-'));
        expect(attributes.some((a) => a.startsWith('Domain'))).toBe(false);
      }),
      runs(),
    );
  });

  it('never writes SameSite=None without Secure', () => {
    fc.assert(
      fc.property(spec, (cookie) => {
        const attributes = serializeCookie(cookie).split('; ').slice(1);

        expect(!attributes.includes('SameSite=None') || attributes.includes('Secure')).toBe(true);
      }),
      runs(),
    );
  });
});

describe('parseCookieHeader', () => {
  const header = fc.oneof(
    fc.string({ unit: 'binary' }),
    fc
      .tuple(
        fc.array(fc.tuple(fc.string(), fc.string()), { maxLength: 6 }),
        fc.constantFrom(';', '; ', ' ;'),
      )
      .map(([pairs, separator]) => pairs.map(([n, v]) => `${n}=${v}`).join(separator)),
  );

  it('never throws, and never returns a name that contains ; or surrounding whitespace', () => {
    fc.assert(
      fc.property(header, (raw) => {
        const cookies = parseCookieHeader(raw);

        for (const name of cookies.keys()) {
          expect(name).not.toContain(';');
          expect(name).toBe(name.trim());
        }

        expect(cookies).toBeInstanceOf(Map);
      }),
      runs(),
    );
  });

  it('keeps the first of duplicate names', () => {
    fc.assert(
      fc.property(
        baseName,
        fc.string({ unit: 'grapheme', maxLength: 20 }),
        fc.string({ unit: 'grapheme', maxLength: 20 }),
        fc.array(baseName, { maxLength: 4 }),
        (name, first, later, between) => {
          const fillers = between.filter((other) => other !== name).map((other) => `${other}=x`);

          const raw = [
            `${name}=${encodeURIComponent(first)}`,
            ...fillers,
            `${name}=${encodeURIComponent(later)}`,
          ].join('; ');

          expect(parseCookieHeader(raw).get(name)).toBe(first);
        },
      ),
      runs(),
    );
  });
});
