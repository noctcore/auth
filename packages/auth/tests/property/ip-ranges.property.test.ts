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
        if (isIp(text)) expect(isIP(text)).not.toBe(0);
      }),
      runs(),
    );
  });
});

describe('isTrustedAddress', () => {
  it('agrees with BlockList for IPv4 ranges', () => {
    fc.assert(
      fc.property(fc.ipV4(), fc.integer({ min: 0, max: 32 }), fc.ipV4(), (net, prefix, ip) => {
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

        // BlockList also matches an IPv4-mapped address against IPv4 rules;
        // with only an IPv6 rule the two must agree exactly.
        expect(isTrustedAddress(ip, [`${net}/${prefix}`])).toBe(list.check(ip, 'ipv6'));
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
      fc.property(fc.string(), (header) => {
        const ip = clientIp({ remoteAddress: '10.0.0.2', trustedHops: 1, trustedHeader: header });

        expect(ip === '10.0.0.2' || (ip !== undefined && isIp(ip))).toBe(true);
      }),
      runs(),
    );
  });
});
