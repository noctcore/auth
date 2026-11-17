// A018: cookie tossing and reading the session cookie from script.
//
// A sibling subdomain sets or overwrites the session cookie (cookie tossing), or an
// injected script reads the cookie and sends it away.
//
// Stopped by: http/cookie.ts: the __Host- prefix whenever the cookie is Secure (no Domain,
//   Path=/), HttpOnly always, SameSite=None refused without Secure.
// Learn: Sessions and expiry (/auth/learn/sessions-and-expiry/)
import { describe, expect, it } from 'vitest';

import { createSessionCookie, serializeCookie, sessionCookieName } from '../../src/http/cookie';
import { AuthConfigError } from '../../src/shared/errors';

describe('A018: cookie tossing and reading the session cookie from script', () => {
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

  it('refuses SameSite=None without Secure, fixed or chosen per origin', () => {
    const at = { expiresAt: 61_000, persistent: true, now: 0 };

    expect(() => createSessionCookie({ sameSite: 'none', secure: false }, 't', at)).toThrow(
      AuthConfigError,
    );

    expect(() =>
      createSessionCookie({ sameSite: () => 'none', secure: false }, 't', {
        ...at,
        origin: 'https://x.example',
      }),
    ).toThrow('SameSite=None requires a Secure cookie');

    expect(createSessionCookie({ sameSite: 'none' }, 't', at).attributes.secure).toBe(true);
  });
});
