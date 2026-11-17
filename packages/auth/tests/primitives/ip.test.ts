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
    expect(
      clientIp({ remoteAddress: '10.0.0.2', forwardedFor: '192.0.2.34', trustedHops: 0 }),
    ).toBe('10.0.0.2');
  });

  it('takes the address one hop to the left of the trusted proxies', () => {
    // A client spoofs 198.51.100.66; the real client 192.0.2.34 is what the one proxy appended.
    expect(
      clientIp({
        remoteAddress: '10.0.0.2',
        forwardedFor: '198.51.100.66, 192.0.2.34',
        trustedHops: 1,
      }),
    ).toBe('192.0.2.34');

    expect(
      clientIp({
        remoteAddress: '10.0.0.3',
        forwardedFor: ['198.51.100.66, 192.0.2.34', '10.0.0.2'],
        trustedHops: 2,
      }),
    ).toBe('192.0.2.34');
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

  it('pads a compressed IPv6 address with fewer than three leading groups', () => {
    expect(maskIp('2001:db8::1')).toBe('2001:db8:0::');
    expect(maskIp('::1')).toBe('0:0:0::');
  });
});

describe('clientIp edges', () => {
  it('has no answer when there is neither a header nor a socket address', () => {
    expect(clientIp({ remoteAddress: undefined, trustedHops: 1 })).toBeUndefined();

    expect(
      clientIp({ remoteAddress: undefined, forwardedFor: ' , ', trustedHops: 1 }),
    ).toBeUndefined();
  });

  it('reads a repeated header the same as one joined header', () => {
    const joined = clientIp({
      remoteAddress: '10.0.0.1',
      forwardedFor: '198.51.100.1, 203.0.113.2',
      trustedHops: 1,
    });

    const repeated = clientIp({
      remoteAddress: '10.0.0.1',
      forwardedFor: ['198.51.100.1', '203.0.113.2'],
      trustedHops: 1,
    });

    expect(joined).toBe('203.0.113.2');
    expect(repeated).toBe(joined);
  });
});

describe('clientIp and maskIp boundaries', () => {
  it('counts hops over the header alone when the socket address is missing', () => {
    for (const remoteAddress of [undefined, ''])
      expect(
        clientIp({ remoteAddress, forwardedFor: '198.51.100.1, 10.0.0.1', trustedHops: 1 }),
      ).toBe('198.51.100.1');
  });

  it('says why it refuses trust proxy "true"', () =>
    expect(() => parseTrustProxy('true')).toThrow(
      'trust proxy "true" lets any client choose its own IP; set the number of proxy hops',
    ));

  it('masks only a whole dotted quad as IPv4', () => {
    expect(maskIp('1.22.3.4')).toBe('1.22.3.0');
    expect(maskIp('x1.2.3.4')).toBe('unknown');
    expect(maskIp('1.2.3.4.5')).toBe('unknown');
    expect(maskIp('1.2.3::ffff:.4')).toBe('1.2.3:0:0::');
  });
});
