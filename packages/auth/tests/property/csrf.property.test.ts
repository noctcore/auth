// Properties of the CSRF checks. A double-submit token that verified for
// another binding (another session) or under another secret, or an Origin
// check that a crafted URL could pass, would let a page on another site make
// state-changing requests with the user's cookies attached.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { hmacSha256Hex } from '../../src/crypto/hash';
import {
  createCsrfToken,
  verifyCsrfToken,
  verifyFetchSite,
  verifyRequestOrigin,
} from '../../src/http/csrf';
import { runs } from './runs';

const secret = fc.uint8Array({ minLength: 32, maxLength: 48 });
const binding = fc.string({ unit: 'binary', maxLength: 40 });
const nonceBytes = fc.uint8Array({ minLength: 16, maxLength: 16 });

function mint(key: Uint8Array, bind: string, nonce: Uint8Array): string {
  return createCsrfToken(key, bind, (bytes) => bytes.set(nonce));
}

/** The token a forger would write if they knew the secret, for any nonce string. */
function forge(key: Uint8Array, bind: string, nonce: string): string {
  return `${nonce}.${hmacSha256Hex(key, `csrf:${bind.length}:${bind}:${nonce}`)}`;
}

function verify(token: string, bind: string, secrets: readonly Uint8Array[], header = token) {
  return verifyCsrfToken({ cookieToken: token, headerToken: header, binding: bind, secrets });
}

describe('signed double-submit token', () => {
  it('verifies with the same binding and secret, also behind older secrets', () => {
    fc.assert(
      fc.property(secret, secret, binding, nonceBytes, (key, older, bind, nonce) => {
        const token = mint(key, bind, nonce);

        expect(verify(token, bind, [key])).toBe(true);
        expect(verify(token, bind, [older, key])).toBe(true);
      }),
      runs(),
    );
  });

  it('refuses any other binding and any other secret', () => {
    fc.assert(
      fc.property(
        secret,
        secret,
        binding,
        binding,
        nonceBytes,
        (key, other, bind, otherBind, n) => {
          fc.pre(otherBind !== bind);
          fc.pre(Buffer.compare(key, other) !== 0);

          const token = mint(key, bind, n);

          expect(verify(token, otherBind, [key])).toBe(false);
          expect(verify(token, bind, [other])).toBe(false);
        },
      ),
      runs(),
    );
  });

  it('refuses a header that is not exactly the cookie', () => {
    fc.assert(
      fc.property(secret, binding, nonceBytes, fc.string(), (key, bind, n, header) => {
        const token = mint(key, bind, n);

        fc.pre(header !== token);

        expect(verify(token, bind, [key], header)).toBe(false);

        expect(
          verifyCsrfToken({ cookieToken: token, headerToken: null, binding: bind, secrets: [key] }),
        ).toBe(false);
      }),
      runs(),
    );
  });

  it('refuses a token with any single character changed, truncated or extended', () => {
    fc.assert(
      fc.property(
        secret,
        binding,
        nonceBytes,
        fc.nat(),
        fc.string({ unit: 'binary', minLength: 1, maxLength: 1 }),
        fc.string({ minLength: 1 }),
        (key, bind, n, at, char, extra) => {
          const token = mint(key, bind, n);
          const index = at % token.length;

          fc.pre(token.charAt(index) !== char);

          const changed = `${token.slice(0, index)}${char}${token.slice(index + 1)}`;

          expect(verify(changed, bind, [key])).toBe(false);
          expect(verify(token.slice(0, index), bind, [key])).toBe(false);
          expect(verify(`${token}${extra}`, bind, [key])).toBe(false);
        },
      ),
      runs(),
    );
  });

  it('refuses a correctly signed token whose nonce is not 32 lowercase hex digits', () => {
    const badNonce = fc.oneof(
      nonceBytes.map((bytes) => Buffer.from(bytes).toString('hex').toUpperCase()),
      fc.stringMatching(/^[0-9a-f]{1,31}$/u),
      fc.stringMatching(/^[0-9a-f]{33,64}$/u),
      fc.string({ unit: 'binary', minLength: 1 }).filter((s) => !s.includes('.')),
    );

    fc.assert(
      fc.property(secret, binding, badNonce, (key, bind, nonce) => {
        fc.pre(!/^[0-9a-f]{32}$/u.test(nonce));

        expect(verify(forge(key, bind, nonce), bind, [key])).toBe(false);
      }),
      runs(),
    );
  });

  it('accepts a forged token with a well-formed nonce, so the property above tests the nonce check', () => {
    fc.assert(
      fc.property(secret, binding, nonceBytes, (key, bind, n) => {
        const nonce = Buffer.from(n).toString('hex');

        expect(verify(forge(key, bind, nonce), bind, [key])).toBe(true);
      }),
      runs(),
    );
  });

  it('frames the binding by its length, so no binding and nonce pair reads as another', () => {
    // Without the length prefix, binding `a` with nonce `n` and binding
    // `a:<part of n>` would sign overlapping strings. Try exactly those.
    fc.assert(
      fc.property(
        secret,
        binding,
        nonceBytes,
        nonceBytes,
        fc.integer({ min: 0, max: 32 }),
        (key, a, n, m, cut) => {
          const nonce = Buffer.from(n).toString('hex');
          const token = mint(key, a, n);
          const shifted = `${a}:${nonce.slice(0, cut)}`;
          const shortened = a.slice(0, Math.max(0, a.length - 1 - (cut % 8)));

          expect(verify(token, shifted, [key])).toBe(false);
          fc.pre(shortened !== a);
          expect(verify(token, shortened, [key])).toBe(false);
          expect(verify(mint(key, shifted, m), a, [key])).toBe(false);
        },
      ),
      runs(),
    );
  });
});

const SAFE = ['GET', 'HEAD', 'OPTIONS'];
const safeMethod = fc.constantFrom(...SAFE).chain((method) => fc.mixedCase(fc.constant(method)));

const unsafeMethod = fc.oneof(
  fc.constantFrom('POST', 'PUT', 'PATCH', 'DELETE', 'post', 'Delete'),
  fc.stringMatching(/^[A-Za-z]{1,10}$/u).filter((m) => !SAFE.includes(m.toUpperCase())),
  // A safe method with one letter swapped for any non-ASCII character, including
  // the ones `toUpperCase()` folds into ASCII (long s, dotless i).
  fc
    .tuple(
      fc.constantFrom(...SAFE),
      fc.nat(),
      fc.oneof(
        fc.constantFrom('\u017F', '\u0131'),
        fc.string({ unit: 'grapheme', minLength: 1, maxLength: 1 }),
      ),
    )
    .filter(([, , ch]) => (ch.codePointAt(0) ?? 0) > 0x7f)
    .map(([m, i, ch]) => m.slice(0, i % m.length) + ch + m.slice((i % m.length) + 1)),
);

const scheme = fc.constantFrom('https', 'http', 'app');
const host = fc.domain();
const port = fc.option(fc.integer({ min: 1, max: 65_535 }), { nil: undefined });

const origin = fc
  .tuple(scheme, host, port)
  .map(([s, h, p]) => (p === undefined ? `${s}://${h}` : `${s}://${h}:${p}`));

function originCheck(method: string, value: string | null | undefined, allowed: readonly string[]) {
  return verifyRequestOrigin({ method, origin: value, allowedOrigins: allowed });
}

describe('verifyRequestOrigin', () => {
  it('lets safe methods through whatever the origin', () => {
    fc.assert(
      fc.property(
        safeMethod,
        fc.option(fc.string(), { nil: undefined }),
        fc.array(origin),
        (m, o, a) => {
          expect(originCheck(m, o, a)).toBe(true);
        },
      ),
      runs(),
    );
  });

  it('refuses an unsafe method from an origin not in the allowlist', () => {
    fc.assert(
      fc.property(unsafeMethod, origin, fc.array(origin, { maxLength: 4 }), (m, o, allowed) => {
        const normal = (value: string) => {
          const url = new URL(value);

          return `${url.protocol}//${url.host}`.toLowerCase();
        };

        fc.pre(!allowed.some((a) => normal(a) === normal(o)));

        expect(originCheck(m, o, allowed)).toBe(false);
      }),
      runs(),
    );
  });

  it('refuses the allowed host under another scheme or port', () => {
    fc.assert(
      fc.property(unsafeMethod, host, fc.integer({ min: 1, max: 65_535 }), (m, h, p) => {
        fc.pre(p !== 443);

        const allowed = [`https://${h}`];

        expect(originCheck(m, `http://${h}`, allowed)).toBe(false);
        expect(originCheck(m, `app://${h}`, allowed)).toBe(false);
        expect(originCheck(m, `https://${h}:${p}`, allowed)).toBe(false);
        expect(originCheck(m, `https://${h}:443`, allowed)).toBe(true);
      }),
      runs(),
    );
  });

  it('accepts an allowed origin in any letter case', () => {
    fc.assert(
      fc.property(unsafeMethod, origin, fc.array(origin, { maxLength: 3 }), (m, o, others) => {
        const allowed = [...others, o];

        expect(originCheck(m, o, allowed)).toBe(true);
        expect(originCheck(m, o.toUpperCase(), allowed)).toBe(true);
        expect(originCheck(m, o, [...others, o.toUpperCase()])).toBe(true);
      }),
      runs(),
    );
  });

  it('refuses a missing, empty or null origin on an unsafe method', () => {
    fc.assert(
      fc.property(
        unsafeMethod,
        fc.array(origin),
        fc.constantFrom(undefined, null, '', 'null'),
        (m, a, o) => {
          expect(originCheck(m, o, [...a, 'null'])).toBe(false);
        },
      ),
      runs(),
    );
  });

  it('reads the host after any userinfo, so good@evil is evil', () => {
    fc.assert(
      fc.property(unsafeMethod, host, host, (m, good, evil) => {
        fc.pre(good !== evil);

        const allowed = [`https://${good}`];

        expect(originCheck(m, `https://${good}@${evil}`, allowed)).toBe(false);
        expect(originCheck(m, `https://${evil}@${good}`, allowed)).toBe(true);
        expect(originCheck(m, `https://${good}.${evil}`, allowed)).toBe(false);
      }),
      runs(),
    );
  });

  it('ignores a path, query or fragment after an allowed origin', () => {
    // Browsers never send these in Origin. The check compares scheme, host and
    // port only, so a path cannot widen or narrow what is allowed.
    fc.assert(
      fc.property(
        unsafeMethod,
        origin,
        fc.webPath(),
        fc.webQueryParameters(),
        (m, o, path, query) => {
          expect(originCheck(m, `${o}${path}?${query}#x`, [o])).toBe(true);
          expect(originCheck(m, o, [`${o}${path}`])).toBe(true);
        },
      ),
      runs(),
    );
  });
});

describe('verifyFetchSite', () => {
  const site = fc.oneof(
    fc.constantFrom('same-origin', 'same-site', 'cross-site', 'none', 'Same-Origin', ''),
    fc.string(),
  );

  it('passes unsafe methods only for same-origin, or same-site when allowed', () => {
    fc.assert(
      fc.property(
        unsafeMethod,
        fc.option(site, { nil: undefined }),
        fc.boolean(),
        (m, s, sameSite) => {
          const expected = s === 'same-origin' || (sameSite && s === 'same-site');

          expect(verifyFetchSite({ method: m, secFetchSite: s, allowSameSite: sameSite })).toBe(
            expected,
          );

          expect(verifyFetchSite({ method: m, secFetchSite: s })).toBe(s === 'same-origin');
        },
      ),
      runs(),
    );
  });

  it('passes safe methods whatever the header says', () => {
    fc.assert(
      fc.property(safeMethod, fc.option(site, { nil: null }), (m, s) => {
        expect(verifyFetchSite({ method: m, secFetchSite: s })).toBe(true);
      }),
      runs(),
    );
  });
});
