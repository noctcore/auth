// A105: a forwarded entry that is not one address.
//
// Some gateways write the client's source port into X-Forwarded-For
// (203.0.113.9:51234), and a misconfigured proxy can write anything. If the
// entry at the trusted position were returned as written, a client whose
// source port changes per connection would get a fresh per-IP rate-limit
// bucket on every connection, and the junk would land in audit events and
// session lists.
//
// Stopped by: http/ip.ts: clientIp strips a port, brackets and an IPv6 zone
//   id from the entry it picks, with a hop count or a proxy list, and returns
//   the socket address when what is left is not exactly one IP. Unit and
//   property tests: tests/primitives/ip.test.ts,
//   tests/property/ip.property.test.ts.
// Learn: Trust proxy and client IPs (/auth/learn/trust-proxy-and-client-ips/); core attack A011
import { describe, expect, it } from 'vitest';

import { clientIp } from '../../src/http/ip';
import { resolveTrustedProxies } from '../../src/http/ip-ranges';
import { EMAIL, meta, registered } from './support';

const proxies = resolveTrustedProxies('10.0.0.0/8');

describe('A105: a forwarded entry that is not one address', () => {
  it('reads an entry with a port as the address, with a hop count or a proxy list', () => {
    for (const trustedHops of [1, proxies]) {
      for (const [written, address] of [
        ['203.0.113.9:51234', '203.0.113.9'],
        ['[2001:db8::1]:443', '2001:db8::1'],
      ] as const) {
        expect(clientIp({ remoteAddress: '10.0.0.2', forwardedFor: written, trustedHops })).toBe(
          address,
        );
      }
    }
  });

  it('never returns an entry that is not an IP, with a hop count or a proxy list', () => {
    for (const trustedHops of [1, proxies]) {
      for (const junk of ['not-an-ip', 'unknown', '<script>', '203.0.113.9:99999', 'a:b:c']) {
        expect(
          clientIp({
            remoteAddress: '10.0.0.2',
            forwardedFor: `198.51.100.1, ${junk}`,
            trustedHops,
          }),
        ).toBe('10.0.0.2');
      }
    }
  });

  it('never picks an entry the client wrote when there is no socket address', () => {
    // A fetch adapter with no peer address: the client wrote 6.6.6.6, the one
    // proxy appended 203.0.113.9:51234.
    expect(
      clientIp({
        remoteAddress: undefined,
        forwardedFor: '6.6.6.6, 203.0.113.9:51234',
        trustedHops: 1,
      }),
    ).toBe('203.0.113.9');
  });

  it('keeps a client whose source port changes per connection in one per-IP budget', async () => {
    const { auth } = await registered();
    const reasons: (string | false)[] = [];

    for (let port = 50_000; port < 50_008; port++) {
      const ip = clientIp({
        remoteAddress: '10.0.0.2',
        forwardedFor: `203.0.113.9:${port}`,
        trustedHops: 1,
      });

      const r = await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(ip) });

      reasons.push(!r.ok && r.reason);
    }

    expect(reasons.slice(0, 5)).toEqual(Array(5).fill('wrong_password'));
    expect(reasons.slice(5)).toEqual(Array(3).fill('account_ip_budget'));
  });
});
