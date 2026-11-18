import { describe, expect, it } from 'vitest';

import { clientIp, resolveClientIpHeader, resolveTrustedHops } from '../../src/http/ip';
import type { TRUST_PROXY_PRESETS } from '../../src/http/ip-ranges';
import { isIp, isTrustedAddress, resolveTrustedProxies } from '../../src/http/ip-ranges';
import { AuthConfigError } from '../../src/shared/errors';

describe('isIp', () => {
  it('accepts plain IPv4 and IPv6 addresses', () => {
    for (const ip of [
      '0.0.0.0',
      '203.0.113.7',
      '255.255.255.255',
      '::',
      '::1',
      '2001:db8::1',
      'fe80::1:2:3:4',
      '::ffff:192.0.2.1',
      '2001:DB8:0:0:0:0:0:1',
    ])
      expect(isIp(ip), ip).toBe(true);
  });

  it('refuses anything that is not exactly one address', () => {
    for (const text of [
      '',
      'unknown',
      '256.0.0.1',
      '01.2.3.4',
      '1.2.3',
      '1.2.3.4.5',
      ' 1.2.3.4',
      '1.2.3.4:80',
      '[::1]',
      'fe80::1%eth0',
      '1::2::3',
      '1:2:3:4:5:6:7:8:9',
      '1:2:3:4:5:6:7',
      '::12345',
      '203.0.113.7, 198.51.100.1',
      '1:2:3:4:5:6:7::8',
    ])
      expect(isIp(text), text).toBe(false);
  });
});

describe('resolveTrustedProxies', () => {
  it('expands each Express preset to the ranges Express gives it', () => {
    expect(resolveTrustedProxies('loopback')).toEqual(['127.0.0.1/8', '::1/128']);
    expect(resolveTrustedProxies('linklocal')).toEqual(['169.254.0.0/16', 'fe80::/10']);

    expect(resolveTrustedProxies('uniquelocal')).toEqual([
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      'fc00::/7',
    ]);
  });

  it('mixes presets with explicit addresses and ranges, from a list or a comma string', () => {
    const expected = ['127.0.0.1/8', '::1/128', '203.0.113.0/24', '2001:db8::/32', '198.51.100.9'];

    expect(resolveTrustedProxies(' loopback, 203.0.113.0/24 ,2001:db8::/32, 198.51.100.9')).toEqual(
      expected,
    );

    expect(
      resolveTrustedProxies(['loopback', '203.0.113.0/24', '2001:db8::/32', '198.51.100.9']),
    ).toEqual(expected);
  });

  it('refuses unknown names, bad ranges and empty entries at boot', () => {
    for (const bad of [
      'localhost',
      'Loopback',
      '10.0.0.0/33',
      '::/129',
      '10.0.0.0/08',
      '10.0.0.0/',
      '10.0.0.0/255.0.0.0',
      '300.0.0.0/8',
      '',
      'loopback,',
      'true',
      'constructor',
    ])
      expect(() => resolveTrustedProxies(bad), bad).toThrow(AuthConfigError);
  });
});

describe('isTrustedAddress', () => {
  it('matches each preset range at its edges', () => {
    const cases: [string, keyof typeof TRUST_PROXY_PRESETS, boolean][] = [
      ['127.0.0.1', 'loopback', true],
      ['127.255.255.255', 'loopback', true],
      ['128.0.0.1', 'loopback', false],
      ['::1', 'loopback', true],
      ['::2', 'loopback', false],
      ['169.254.0.1', 'linklocal', true],
      ['169.255.0.1', 'linklocal', false],
      ['fe80::1', 'linklocal', true],
      ['febf:ffff::1', 'linklocal', true],
      ['fec0::1', 'linklocal', false],
      ['10.255.0.1', 'uniquelocal', true],
      ['11.0.0.1', 'uniquelocal', false],
      ['172.16.0.1', 'uniquelocal', true],
      ['172.31.255.255', 'uniquelocal', true],
      ['172.32.0.1', 'uniquelocal', false],
      ['192.168.1.1', 'uniquelocal', true],
      ['192.169.0.1', 'uniquelocal', false],
      ['fc00::1', 'uniquelocal', true],
      ['fdff::1', 'uniquelocal', true],
      ['fe00::1', 'uniquelocal', false],
    ];

    for (const [address, preset, trusted] of cases)
      expect(isTrustedAddress(address, [preset]), `${address} in ${preset}`).toBe(trusted);
  });

  it('matches IPv4-mapped IPv6 socket addresses against IPv4 ranges, as Express does', () => {
    expect(isTrustedAddress('::ffff:127.0.0.1', ['loopback'])).toBe(true);
    expect(isTrustedAddress('::ffff:10.1.2.3', ['10.0.0.0/8'])).toBe(true);
    expect(isTrustedAddress('::ffff:11.1.2.3', ['10.0.0.0/8'])).toBe(false);
    expect(isTrustedAddress('10.1.2.3', ['::ffff:0:0/96'])).toBe(true);
  });

  it('never trusts something that is not an address', () => {
    expect(isTrustedAddress('unknown', ['0.0.0.0/0'])).toBe(false);
    expect(isTrustedAddress('', ['loopback'])).toBe(false);
  });

  it('treats a bare address as a single host and /0 as everything of its family', () => {
    expect(isTrustedAddress('198.51.100.9', ['198.51.100.9'])).toBe(true);
    expect(isTrustedAddress('198.51.100.10', ['198.51.100.9'])).toBe(false);
    expect(isTrustedAddress('203.0.113.1', ['0.0.0.0/0'])).toBe(true);
    expect(isTrustedAddress('2001:db8::1', ['0.0.0.0/0'])).toBe(false);
  });
});

describe('clientIp with a trusted proxy list', () => {
  const proxies = resolveTrustedProxies('loopback, uniquelocal');

  it('skips every trusted address from the socket leftwards', () => {
    expect(
      clientIp({
        remoteAddress: '127.0.0.1',
        forwardedFor: '198.51.100.66, 203.0.113.50, 10.0.0.7',
        trustedHops: proxies,
      }),
    ).toBe('203.0.113.50');
  });

  it('ignores X-Forwarded-For when the socket address is not a trusted proxy', () => {
    expect(
      clientIp({
        remoteAddress: '203.0.113.50',
        forwardedFor: '198.51.100.1',
        trustedHops: proxies,
      }),
    ).toBe('203.0.113.50');
  });

  it('takes the leftmost address when every hop is trusted', () => {
    expect(
      clientIp({
        remoteAddress: '10.0.0.2',
        forwardedFor: '10.0.0.9, 10.0.0.8',
        trustedHops: proxies,
      }),
    ).toBe('10.0.0.9');

    expect(clientIp({ remoteAddress: '10.0.0.2', trustedHops: proxies })).toBe('10.0.0.2');
  });

  it('has no answer without a socket address, and an empty list trusts nothing', () => {
    expect(
      clientIp({ remoteAddress: undefined, forwardedFor: '198.51.100.1', trustedHops: proxies }),
    ).toBeUndefined();

    expect(
      clientIp({ remoteAddress: '10.0.0.2', forwardedFor: '198.51.100.1', trustedHops: [] }),
    ).toBe('10.0.0.2');
  });
});

describe('clientIp with a trusted client IP header', () => {
  it('uses the header when the request came through a trusted hop', () => {
    expect(
      clientIp({
        remoteAddress: '10.0.0.2',
        forwardedFor: '203.0.113.50',
        trustedHops: 1,
        trustedHeader: '198.51.100.7',
      }),
    ).toBe('198.51.100.7');

    expect(
      clientIp({
        remoteAddress: '10.0.0.2',
        trustedHops: ['uniquelocal'],
        trustedHeader: ' 2001:db8::7 ',
      }),
    ).toBe('2001:db8::7');
  });

  it('ignores the header with no trusted hop', () => {
    expect(
      clientIp({ remoteAddress: '203.0.113.50', trustedHops: 0, trustedHeader: '198.51.100.7' }),
    ).toBe('203.0.113.50');

    expect(
      clientIp({
        remoteAddress: '203.0.113.50',
        trustedHops: ['uniquelocal'],
        trustedHeader: '198.51.100.7',
      }),
    ).toBe('203.0.113.50');
  });

  it('falls back to the hop rule when the header is not exactly one address', () => {
    for (const trustedHeader of [
      '',
      'unknown',
      '198.51.100.7, 203.0.113.9',
      '198.51.100.7:443',
      '[2001:db8::7]',
      '256.1.1.1',
      ['198.51.100.7', '203.0.113.9'],
      [],
      null,
      undefined,
    ])
      expect(
        clientIp({
          remoteAddress: '10.0.0.2',
          forwardedFor: '203.0.113.50',
          trustedHops: 1,
          trustedHeader,
        }),
        JSON.stringify(trustedHeader),
      ).toBe('203.0.113.50');

    expect(
      clientIp({ remoteAddress: '10.0.0.2', trustedHops: 1, trustedHeader: ['198.51.100.7'] }),
    ).toBe('198.51.100.7');
  });
});

describe('resolveTrustedHops', () => {
  it('passes a hop count in range and expands a list', () => {
    expect(resolveTrustedHops(0, 16)).toBe(0);
    expect(resolveTrustedHops(16, 16)).toBe(16);

    expect(resolveTrustedHops(['loopback', '203.0.113.0/24'], 16)).toEqual([
      '127.0.0.1/8',
      '::1/128',
      '203.0.113.0/24',
    ]);
  });

  it('refuses counts out of range and lists with bad entries', () => {
    for (const bad of [-1, 17, 1.5, Number.NaN])
      expect(() => resolveTrustedHops(bad, 16)).toThrow(/from 0 to 16/u);

    expect(() => resolveTrustedHops(['localhost'], 16)).toThrow(AuthConfigError);
    expect(() => resolveTrustedHops('loopback' as never, 16)).toThrow(AuthConfigError);
  });
});

describe('resolveClientIpHeader', () => {
  it('lowercases a header name and passes undefined through', () => {
    expect(resolveClientIpHeader('CF-Connecting-IP')).toBe('cf-connecting-ip');
    expect(resolveClientIpHeader(undefined)).toBeUndefined();
  });

  it('refuses X-Forwarded-For and names that are not header names', () => {
    for (const bad of ['X-Forwarded-For', '', 'cf connecting ip', 'a:b'])
      expect(() => resolveClientIpHeader(bad), bad).toThrow(AuthConfigError);
  });
});
