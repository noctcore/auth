import { describe, expect, it } from 'vitest';

import { AuthConfigError } from '../../src/shared/errors';
import { clientIp, maskIp, parseTrustProxy } from '../../src/http/ip';

describe('parseTrustProxy', () => {
  it('turns an all-digit value into a hop count', () => expect(parseTrustProxy(' 1 ')).toBe(1));

  it('passes presets and address lists through', () =>
    expect(parseTrustProxy('loopback')).toBe('loopback'));

  it('treats empty and false as no proxy', () => {
    expect(parseTrustProxy(undefined)).toBe(false);
    expect(parseTrustProxy('')).toBe(false);
    expect(parseTrustProxy('false')).toBe(false);
  });

  it('refuses true, which lets clients pick their IP', () =>
    expect(() => parseTrustProxy('true')).toThrow(AuthConfigError));
});

describe('clientIp', () => {
  it('ignores X-Forwarded-For with no trusted hops', () => {
    expect(clientIp({ remoteAddress: '10.0.0.2', forwardedFor: '1.2.3.4', trustedHops: 0 })).toBe(
      '10.0.0.2',
    );
  });

  it('takes the address one hop to the left of the trusted proxies', () => {
    // A client spoofs 6.6.6.6; the real client 1.2.3.4 is what the one proxy appended.
    expect(
      clientIp({ remoteAddress: '10.0.0.2', forwardedFor: '6.6.6.6, 1.2.3.4', trustedHops: 1 }),
    ).toBe('1.2.3.4');

    expect(
      clientIp({
        remoteAddress: '10.0.0.3',
        forwardedFor: ['6.6.6.6, 1.2.3.4', '10.0.0.2'],
        trustedHops: 2,
      }),
    ).toBe('1.2.3.4');
  });

  it('clamps when there are fewer hops than configured', () => {
    expect(clientIp({ remoteAddress: '10.0.0.2', forwardedFor: undefined, trustedHops: 3 })).toBe(
      '10.0.0.2',
    );
  });
});

describe('maskIp', () => {
  it('coarsens IPv4 to /24 and IPv6 to /48', () => {
    expect(maskIp('203.0.113.77')).toBe('203.0.113.0');
    expect(maskIp('::ffff:203.0.113.77')).toBe('203.0.113.0');
    expect(maskIp('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::');
    expect(maskIp('garbage')).toBe('unknown');
  });
});
