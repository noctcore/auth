// Properties of the client IP behind proxies. Every per-IP limit keys on this
// value: if an attacker's own X-Forwarded-For entries could win, any client
// could pick its own rate-limit bucket, and a misread TRUST_PROXY setting
// could silently trust every hop or none.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { clientIp, parseTrustProxy } from '../../src/http/ip';
import { isIp, isTrustedAddress } from '../../src/http/ip-ranges';
import { AuthConfigError } from '../../src/shared/errors';
import { runs } from './runs';

/** One address as a proxy writes it: no comma, no surrounding whitespace. */
const address = fc.oneof(
  fc.ipV4(),
  fc.ipV6(),
  fc
    .string({ minLength: 1, maxLength: 20 })
    .map((s) => s.replaceAll(',', '').trim())
    .filter((s) => s !== ''),
);

/** An X-Forwarded-For entry a proxy writes: one IP address. */
const entry = fc.oneof(fc.ipV4(), fc.ipV6());

/** Text with no comma that `clientIp` cannot read as an IP, even after a port, brackets or a zone id. */
const junk = fc
  .string({ minLength: 1, maxLength: 20 })
  .map((s) => s.replaceAll(',', '').trim())
  .filter((s) => {
    const bare = s
      .replace(/^\[(.*)\](:\d*)?$/u, '$1')
      .replace(/:\d{1,5}$/u, '')
      .split('%')[0];

    return s !== '' && !isIp(s) && !isIp(bare ?? '');
  });

const whitespace = fc.string({ unit: fc.constantFrom(' ', '\t'), maxLength: 3 });

describe('clientIp', () => {
  it('returns the socket address with 0 hops, whatever X-Forwarded-For says', () => {
    fc.assert(
      fc.property(
        fc.option(address, { nil: undefined }),
        fc.option(fc.oneof(fc.string(), fc.array(fc.string())), { nil: undefined }),
        fc.integer({ min: -5, max: 0 }),
        (remote, header, hops) => {
          expect(clientIp({ remoteAddress: remote, forwardedFor: header, trustedHops: hops })).toBe(
            remote,
          );
        },
      ),
      runs(),
    );
  });

  it('returns what the first trusted proxy saw, whatever the client prepends', () => {
    // client -> proxy 1 -> ... -> proxy N -> server. Proxy 1 appends the
    // client's address, each later proxy appends the one before it, and the
    // socket address is proxy N. Everything left of that is the client's.
    fc.assert(
      fc.property(
        fc.array(entry, { maxLength: 6 }),
        fc.array(entry, { minLength: 1, maxLength: 5 }),
        address,
        (spoofed, genuine, remote) => {
          const hops = genuine.length;
          const header = [...spoofed, ...genuine].join(', ');

          expect(clientIp({ remoteAddress: remote, forwardedFor: header, trustedHops: hops })).toBe(
            genuine[0],
          );
        },
      ),
      runs(),
    );
  });

  it('falls back to the leftmost entry only when the chain is shorter than the hops', () => {
    fc.assert(
      fc.property(
        fc.array(entry, { maxLength: 5 }),
        address,
        fc.integer({ min: 1, max: 5 }),
        (entries, remote, extra) => {
          // The chain is the entries plus the socket address, so it is
          // shorter than the hops plus one exactly when hops > entries.
          const hops = entries.length + extra;

          const result = clientIp({
            remoteAddress: remote,
            forwardedFor: entries.join(','),
            trustedHops: hops,
          });

          expect(result).toBe(entries[0] ?? remote);
        },
      ),
      runs(),
    );
  });

  it('returns the socket address when the picked entry is not an IP, with a count or a list', () => {
    fc.assert(
      fc.property(
        fc.array(fc.oneof(entry, junk), { maxLength: 4 }),
        junk,
        fc.array(
          fc.ipV4().map((ip) => `10.${ip.split('.').slice(1).join('.')}`),
          {
            maxLength: 3,
          },
        ),
        (spoofed, bad, proxies) => {
          const header = [...spoofed, bad, ...proxies].join(', ');
          const remote = '10.0.0.1';

          expect(
            clientIp({
              remoteAddress: remote,
              forwardedFor: header,
              trustedHops: proxies.length + 1,
            }),
          ).toBe(remote);

          expect(
            clientIp({ remoteAddress: remote, forwardedFor: header, trustedHops: ['10.0.0.0/8'] }),
          ).toBe(remote);
        },
      ),
      runs(),
    );
  });

  it('strips a port from the picked entry, with a count or a list', () => {
    fc.assert(
      fc.property(fc.ipV4(), fc.ipV6(), fc.integer({ min: 0, max: 65535 }), (v4, v6, port) => {
        fc.pre(!isTrustedAddress(v4, ['10.0.0.0/8']) && !isTrustedAddress(v6, ['10.0.0.0/8']));

        for (const [written, address] of [
          [`${v4}:${port}`, v4],
          [`[${v6}]:${port}`, v6],
        ] as const) {
          const input = { remoteAddress: '10.0.0.1', forwardedFor: `192.0.2.1, ${written}` };

          expect(clientIp({ ...input, trustedHops: 1 })).toBe(address);
          expect(clientIp({ ...input, trustedHops: ['10.0.0.0/8'] })).toBe(address);
        }
      }),
      runs(),
    );
  });

  it('gives the same answer for a string header and the same entries split into an array', () => {
    fc.assert(
      fc.property(
        fc.array(fc.oneof(entry, junk), { maxLength: 8 }),
        fc.array(fc.nat(), { maxLength: 4 }),
        fc.option(address, { nil: undefined }),
        fc.integer({ min: 1, max: 6 }),
        (entries, cuts, remote, hops) => {
          const points = [...new Set(cuts.map((c) => c % (entries.length + 1)))].sort(
            (a, b) => a - b,
          );

          const parts = [0, ...points, entries.length]
            .slice(0, -1)
            .map((start, i, starts) =>
              entries.slice(start, starts[i + 1] ?? entries.length).join(','),
            );

          expect(clientIp({ remoteAddress: remote, forwardedFor: parts, trustedHops: hops })).toBe(
            clientIp({ remoteAddress: remote, forwardedFor: entries.join(','), trustedHops: hops }),
          );
        },
      ),
      runs(),
    );
  });

  it('ignores whitespace around entries and empty entries', () => {
    fc.assert(
      fc.property(
        fc.array(fc.oneof(entry, junk), { maxLength: 8 }),
        fc.array(fc.tuple(whitespace, whitespace, fc.nat(2)), { minLength: 8, maxLength: 8 }),
        address,
        fc.integer({ min: 1, max: 6 }),
        (entries, noise, remote, hops) => {
          const messy = entries
            .map((entry, i) => {
              const [before, after, empties] = noise[i] ?? ['', '', 0];

              return [`${before}${entry}${after}`, ...Array<string>(empties).fill(before)].join(
                ',',
              );
            })
            .join(',');

          expect(clientIp({ remoteAddress: remote, forwardedFor: messy, trustedHops: hops })).toBe(
            clientIp({ remoteAddress: remote, forwardedFor: entries.join(','), trustedHops: hops }),
          );
        },
      ),
      runs(),
    );
  });
});

describe('parseTrustProxy', () => {
  it('reads an all-digit value, whitespace around it allowed, as that hop count', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^\d{1,6}$/u), whitespace, whitespace, (digits, a, b) => {
        expect(parseTrustProxy(`${a}${digits}${b}`)).toBe(Number(digits));
      }),
      runs(),
    );
  });

  it('refuses true, and reads empty, false and unset as no proxy', () => {
    fc.assert(
      fc.property(whitespace, whitespace, (a, b) => {
        expect(() => parseTrustProxy(`${a}true${b}`)).toThrow(AuthConfigError);
        expect(parseTrustProxy(`${a}false${b}`)).toBe(false);
        expect(parseTrustProxy(`${a}${b}`)).toBe(false);
        expect(parseTrustProxy(undefined)).toBe(false);
      }),
      runs(),
    );
  });

  it('passes everything else through trimmed', () => {
    fc.assert(
      fc.property(fc.string(), (raw) => {
        const value = raw.trim();

        fc.pre(!['', 'true', 'false'].includes(value) && !/^\d+$/u.test(value));

        expect(parseTrustProxy(raw)).toBe(value);
      }),
      runs(),
    );
  });
});
