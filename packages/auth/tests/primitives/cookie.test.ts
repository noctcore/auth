import { describe, expect, it } from 'vitest';

import {
  createBlankSessionCookie,
  createSessionCookie,
  deviceCookie,
  deviceCookieName,
  parseCookieHeader,
  serializeCookie,
  sessionCookieName,
} from '../../src/http/cookie';
import { AuthConfigError } from '../../src/shared/errors';

describe('session cookie', () => {
  it('is a browser-session cookie when the session was not remembered', () => {
    const spec = createSessionCookie({}, 't', { expiresAt: 61_000, persistent: false, now: 0 });

    expect(spec.attributes.maxAge).toBeUndefined();
  });

  it('picks SameSite per origin and refuses None without Secure', () => {
    const sameSite = (origin: string | undefined) => (origin === 'app://app' ? 'none' : 'lax');

    expect(
      createSessionCookie({ sameSite }, 't', {
        expiresAt: 0,
        persistent: false,
        now: 0,
        origin: 'app://app',
      }).attributes.sameSite,
    ).toBe('none');

    expect(() => createBlankSessionCookie({ secure: false, sameSite: 'none' })).toThrow(
      AuthConfigError,
    );
  });

  it('clears with Max-Age=0', () => {
    expect(serializeCookie(createBlankSessionCookie({}))).toContain('Max-Age=0');
  });
});

describe('parseCookieHeader', () => {
  it('keeps the first value of a duplicated name and skips malformed escapes', () => {
    const cookies = parseCookieHeader('a=1; b=%E0%A4%A; a=2; c=x%20y');

    expect(cookies.get('a')).toBe('1');
    expect(cookies.has('b')).toBe(false);
    expect(cookies.get('c')).toBe('x y');
  });
});

describe('cookie edges', () => {
  it('refuses a cookie name that could break the header', () => {
    for (const name of ['bad name', 'a;b', 'a=b', '', 'caf\u00e9'])
      expect(() => sessionCookieName({ name })).toThrow(AuthConfigError);
  });

  it('names the device cookie __Host-device only when it is Secure', () => {
    expect(deviceCookieName()).toBe('__Host-device');
    expect(deviceCookieName({ secure: false })).toBe('device');

    expect(deviceCookie({}, 'tok', 60).attributes).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 60,
    });
  });

  it('writes only the attributes a spec sets', () => {
    expect(
      serializeCookie({
        name: 'n',
        value: 'a b;c',
        attributes: { httpOnly: false, secure: false, sameSite: 'strict', path: '/' },
      }),
    ).toBe('n=a%20b%3Bc; Path=/; SameSite=Strict');
  });

  it('skips pairs without a name or an equals sign', () => {
    const cookies = parseCookieHeader('=x; novalue; ; a=1');

    expect([...cookies.entries()]).toEqual([['a', '1']]);
    expect(parseCookieHeader(undefined).size).toBe(0);
    expect(parseCookieHeader(null).size).toBe(0);
  });
});
