// A078: choosing your own IP with a spoofed edge header.
//
// The app reads the client IP from a header its edge sets, such as
// cf-connecting-ip. An attacker who reaches the server without going through
// that edge (or through a proxy the app does not trust) sends the header
// themselves, with a fresh address per request, to get a fresh rate-limit
// bucket each time. A garbage value tries to put everyone in one bucket.
//
// Stopped by: http/ip.ts: clientIp honors the trusted header only when the
//   request came through a trusted hop (a hop count above 0, or a socket
//   address inside the trusted proxy list) and only when it holds exactly one
//   valid IP; otherwise the X-Forwarded-For rule decides.
//   resolveClientIpHeader refuses X-Forwarded-For as the header.
//   Unit and property tests: tests/primitives/ip-ranges.test.ts,
//   tests/property/ip-ranges.property.test.ts.
// Learn: Trust proxy and client IPs (/auth/learn/trust-proxy-and-client-ips/); core attack A011
import { describe, expect, it } from 'vitest';

import { clientIp, resolveClientIpHeader } from '../../src/http/ip';
import { resolveTrustedProxies } from '../../src/http/ip-ranges';
import { AuthConfigError } from '../../src/shared/errors';
import { EMAIL, meta, registered } from './support';

const edge = resolveTrustedProxies('uniquelocal');

describe('A078: choosing your own IP with a spoofed edge header', () => {
  it('ignores the header from a peer outside the trusted proxy list', () => {
    for (const spoofed of ['198.51.100.11', '127.0.0.1', '::1', '10.0.0.1']) {
      expect(
        clientIp({ remoteAddress: '203.0.113.50', trustedHops: edge, trustedHeader: spoofed }),
      ).toBe('203.0.113.50');
    }
  });

  it('ignores the header when no proxy is trusted at all', () => {
    expect(
      clientIp({ remoteAddress: '203.0.113.50', trustedHops: 0, trustedHeader: '198.51.100.11' }),
    ).toBe('203.0.113.50');
  });

  it('uses the header the edge set when the request came through the trusted proxy', () => {
    expect(
      clientIp({ remoteAddress: '10.0.0.2', trustedHops: edge, trustedHeader: '198.51.100.11' }),
    ).toBe('198.51.100.11');
  });

  it('falls back to the hop rule for a value that is not exactly one address', () => {
    for (const garbage of ['unknown', '', '198.51.100.11, 198.51.100.12', '198.51.100.11:1234']) {
      expect(
        clientIp({
          remoteAddress: '10.0.0.2',
          forwardedFor: '203.0.113.50',
          trustedHops: edge,
          trustedHeader: garbage,
        }),
      ).toBe('203.0.113.50');
    }
  });

  it('refuses X-Forwarded-For as the trusted header', () =>
    expect(() => resolveClientIpHeader('X-Forwarded-For')).toThrow(AuthConfigError));

  it('keeps a direct client rotating spoofed headers in one per-IP budget', async () => {
    const { auth } = await registered();
    const reasons: (string | false)[] = [];

    for (let i = 0; i < 8; i++) {
      const ip = clientIp({
        remoteAddress: '203.0.113.50',
        trustedHops: edge,
        trustedHeader: `198.51.100.${i}`,
      });

      const r = await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(ip) });

      reasons.push(!r.ok && r.reason);
    }

    expect(reasons.slice(0, 5)).toEqual(Array(5).fill('wrong_password'));
    expect(reasons.slice(5)).toEqual(Array(3).fill('account_ip_budget'));
  });
});
