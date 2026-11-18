// Properties of trusting proxies by address. A range check that is off by one
// bit trusts a client as a proxy (and lets it write its own IP), so the
// matcher is checked against Node's own BlockList, and a header the edge sets
// must never win for a request that did not come through a trusted proxy.
import { BlockList, isIP } from 'node:net';

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { clientIp } from '../../src/http/ip';
import { isIp, isTrustedAddress } from '../../src/http/ip-ranges';
import { runs } from './runs';

/**
 * Strings shaped like addresses: fragments of digits, hex, dots and colons
 * glued together, so the parser sees near misses ("1.2.3.4::5", ":::1",
 * "1:2::3.4.5.6") far more often than plain random text would produce.
 */
const ipShaped = fc
  .array(
    fc.oneof(
      fc.constantFrom('.', ':', '::', '0', '1', '255', '256', '01', 'ffff', 'fe80', 'g'),
      fc.integer({ min: 0, max: 300 }).map(String),
      fc.integer({ min: 0, max: 0xfffff }).map((n) => n.toString(16)),
      fc.ipV4(),
      fc.ipV6(),
    ),
    { minLength: 1, maxLength: 10 },
  )
  .map((parts) => parts.join(''));

describe('isIp', () => {
  it('accepts every address fast-check generates, as Node does', () => {
    fc.assert(
      fc.property(fc.oneof(fc.ipV4(), fc.ipV6()), (ip) => {
        expect(isIp(ip)).toBe(true);
        expect(isIP(ip)).not.toBe(0);
      }),
      runs(),
    );
  });

  it('never accepts a string Node does not read as an address', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 45 }), (text) => {
        expect(!isIp(text) || isIP(text) !== 0).toBe(true);
      }),
      runs(),
    );
  });

  it('agrees with Node on address-shaped near misses', () => {
    fc.assert(
      fc.property(ipShaped, (text) => {
        // Node also accepts zone ids, which this parser refuses on purpose.
        const node = text.includes('%') ? 0 : isIP(text);

        expect(isIp(text)).toBe(node !== 0);
      }),
      runs(),
    );
  });
});

describe('isTrustedAddress', () => {
  it('agrees with BlockList for IPv4 ranges', () => {
    fc.assert(
      // /0 trusts everything and is refused (a list holding it trusts nothing).
      fc.property(fc.ipV4(), fc.integer({ min: 1, max: 32 }), fc.ipV4(), (net, prefix, ip) => {
        const list = new BlockList();

        list.addSubnet(net, prefix, 'ipv4');

        expect(isTrustedAddress(ip, [`${net}/${prefix}`])).toBe(list.check(ip, 'ipv4'));
      }),
      runs(),
    );
  });

  it('agrees with BlockList for IPv6 ranges', () => {
    fc.assert(
      fc.property(fc.ipV6(), fc.integer({ min: 0, max: 128 }), fc.ipV6(), (net, prefix, ip) => {
        const list = new BlockList();

        list.addSubnet(net, prefix, 'ipv6');

        // A range holding every IPv4 address through its mapped form trusts
        // everything and is refused, so a list holding it trusts nothing.
        // Otherwise, with only an IPv6 rule, the two agree exactly.
        const holdsEverything = prefix <= 96 && list.check('::ffff:0.0.0.0', 'ipv6');

        expect(isTrustedAddress(ip, [`${net}/${prefix}`])).toBe(
          !holdsEverything && list.check(ip, 'ipv6'),
        );
      }),
      runs(),
    );
  });
});

describe('clientIp with a trusted header', () => {
  it('never lets the header pick the IP for a peer outside the trusted list', () => {
    fc.assert(
      fc.property(
        fc.ipV4().filter((ip) => !ip.startsWith('10.')),
        fc.oneof(fc.ipV4(), fc.ipV6(), fc.string()),
        fc.option(fc.string(), { nil: undefined }),
        (peer, header, forwardedFor) => {
          expect(
            clientIp({
              remoteAddress: peer,
              forwardedFor,
              trustedHops: ['10.0.0.0/8'],
              trustedHeader: header,
            }),
          ).toBe(peer);
        },
      ),
      runs(),
    );
  });

  it('never returns a header value that is not one address', () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), ipShaped), (header) => {
        const ip = clientIp({
          remoteAddress: '10.0.0.2',
          trustedHops: ['10.0.0.0/8'],
          trustedHeader: header,
        });

        expect(ip === '10.0.0.2' || (ip !== undefined && isIp(ip))).toBe(true);
      }),
      runs(),
    );
  });

  it('never lets the header win with a hop count, which never checks the socket', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 16 }), ipShaped, (hops, header) => {
        expect(
          clientIp({ remoteAddress: '203.0.113.50', trustedHops: hops, trustedHeader: header }),
        ).not.toBe(header.trim() === '203.0.113.50' ? 'never' : header.trim());
      }),
      runs(),
    );
  });
});
