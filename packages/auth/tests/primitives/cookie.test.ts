import { describe, expect, it } from 'vitest';

import {
  createBlankSessionCookie,
  createSessionCookie,
  parseCookieHeader,
  serializeCookie,
  sessionCookieName,
} from '../../src/cookie';
import { AuthConfigError } from '../../src/errors';

describe('session cookie', () => {
  it('uses the __Host- prefix whenever it is Secure', () => {
    expect(sessionCookieName()).toBe('__Host-session');
    expect(sessionCookieName({ name: 'sid', secure: false })).toBe('sid');
  });

  it('is HttpOnly, Path=/, Lax by default and has no Domain', () => {
    const spec = createSessionCookie({}, 't', { expiresAt: 61_000, persistent: true, now: 0 });
    expect(spec.attributes).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 61,
    });
    expect(serializeCookie(spec)).toBe(
      '__Host-session=t; Path=/; Max-Age=61; HttpOnly; Secure; SameSite=Lax',
    );
  });

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
