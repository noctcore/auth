// A011: spoofing the client IP.
//
// An attacker sends their own X-Forwarded-For entries to pick a fresh rate-limit
// bucket per request, or an app trusts every hop so the client chooses its IP.
//
// Stopped by: http/ip.ts: clientIp counts trusted hops from the right; parseTrustProxy
//   refuses "true". Unit and property tests: tests/primitives/ip.test.ts,
//   tests/property/ip.property.test.ts.
// Learn: Trust proxy and client IPs (planned); Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import { clientIp, parseTrustProxy } from '../../src/http/ip';
import { AuthConfigError } from '../../src/shared/errors';
import { EMAIL, meta, registered } from './support';

describe('A011: spoofing the client IP', () => {
  it('never lets entries the client wrote pick the IP behind one trusted proxy', () => {
    // The client sends its own X-Forwarded-For; the proxy appends the address it saw.
    for (const spoofed of ['1.1.1.1', '10.0.0.1, 8.8.8.8', 'unknown, ::1, 127.0.0.1']) {
      expect(
        clientIp({
          remoteAddress: '10.0.0.2',
          forwardedFor: `${spoofed}, 203.0.113.50`,
          trustedHops: 1,
        }),
      ).toBe('203.0.113.50');
    }
  });

  it('ignores the header entirely with no proxy, and refuses "trust every hop"', () => {
    expect(
      clientIp({ remoteAddress: '203.0.113.50', forwardedFor: '1.1.1.1', trustedHops: 0 }),
    ).toBe('203.0.113.50');

    expect(() => parseTrustProxy('true')).toThrow(AuthConfigError);
    expect(parseTrustProxy('1')).toBe(1);
  });

  it('keeps a client rotating spoofed headers in one per-IP budget', async () => {
    const { auth } = await registered();
    const reasons: (string | false)[] = [];

    for (let i = 0; i < 8; i++) {
      const ip = clientIp({
        remoteAddress: '10.0.0.2',
        forwardedFor: `198.51.100.${i}, 203.0.113.50`,
        trustedHops: 1,
      });

      const r = await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(ip) });

      reasons.push(!r.ok && r.reason);
    }

    expect(reasons.slice(0, 5)).toEqual(Array(5).fill('wrong_password'));
    expect(reasons.slice(5)).toEqual(Array(3).fill('account_ip_budget'));
  });
});
