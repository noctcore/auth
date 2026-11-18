// A079: posing as a trusted proxy.
//
// The app trusts its proxies by address (a CIDR list or the Express presets
// loopback, linklocal and uniquelocal). An attacker connects from an address
// outside that list and writes X-Forwarded-For entries, hoping the server
// skips them like a proxy's, or a misspelled preset quietly trusts nothing or
// everything.
//
// Stopped by: http/ip.ts: with a proxy list, clientIp reads X-Forwarded-For
//   only when the socket address is inside the list, and then skips only the
//   entries inside it, right to left. http/ip-ranges.ts:
//   resolveTrustedProxies expands each preset to the ranges Express gives it
//   and refuses any entry that is not a preset, an address or a CIDR range.
//   Unit and property tests: tests/primitives/ip-ranges.test.ts,
//   tests/property/ip-ranges.property.test.ts.
// Learn: Trust proxy and client IPs (/auth/learn/trust-proxy-and-client-ips/); core attack A011
import { describe, expect, it } from 'vitest';

import { clientIp } from '../../src/http/ip';
import { resolveTrustedProxies } from '../../src/http/ip-ranges';
import { AuthConfigError } from '../../src/shared/errors';

const proxies = resolveTrustedProxies('loopback, 192.0.2.0/24');

describe('A079: posing as a trusted proxy', () => {
  it('ignores X-Forwarded-For from a peer outside the trusted list', () => {
    for (const forged of ['198.51.100.11', '127.0.0.1', '192.0.2.10, 198.51.100.88']) {
      expect(
        clientIp({ remoteAddress: '203.0.113.50', forwardedFor: forged, trustedHops: proxies }),
      ).toBe('203.0.113.50');
    }
  });

  it('stops at the first untrusted entry, so entries the client wrote before it never win', () => {
    expect(
      clientIp({
        remoteAddress: '127.0.0.1',
        forwardedFor: '198.51.100.11, 192.0.2.99, 203.0.113.50, 192.0.2.10',
        trustedHops: proxies,
      }),
    ).toBe('203.0.113.50');
  });

  it('does not trust addresses next to a range', () => {
    for (const outside of ['192.0.3.1', '128.0.0.1', '::2']) {
      expect(
        clientIp({ remoteAddress: outside, forwardedFor: '198.51.100.11', trustedHops: proxies }),
      ).toBe(outside);
    }
  });

  it('refuses a misspelled preset or a malformed range instead of guessing', () => {
    for (const typo of ['localhost', 'loopbak', 'uniquelocal,', '10.0.0.0/33', '*', 'true'])
      expect(() => resolveTrustedProxies(typo), typo).toThrow(AuthConfigError);
  });
});
