// A008: cross-site request forgery.
//
// A page on another site makes the victim's browser POST to the app with the
// session cookie attached, or replays a CSRF token taken from the attacker's own
// session.
//
// Stopped by: http/csrf.ts: the Origin allowlist, the Sec-Fetch-Site check and the signed
//   double-submit token bound to the session; http/cookie.ts (SameSite=Lax).
//   Unit and property tests: tests/primitives/csrf.test.ts, tests/property/csrf.property.test.ts.
// Learn: CSRF (/auth/learn/csrf/)
import { describe, expect, it } from 'vitest';

import {
  createCsrfToken,
  verifyCsrfToken,
  verifyFetchSite,
  verifyRequestOrigin,
} from '../../src/http/csrf';
import { EMAIL, setup } from './support';

describe('A008: cross-site request forgery', () => {
  const ALLOWED = ['https://app.example', 'app://desktop'];
  const secret = new TextEncoder().encode('csrf-secret-csrf-secret-csrf-sec');

  it('refuses a cross-site POST by its Origin, by Sec-Fetch-Site, and without the token', () => {
    const forged = { method: 'POST', origin: 'https://evil.example', allowedOrigins: ALLOWED };

    expect(verifyRequestOrigin(forged)).toBe(false);
    expect(verifyRequestOrigin({ ...forged, origin: null })).toBe(false);
    expect(verifyRequestOrigin({ ...forged, origin: 'null' })).toBe(false);

    expect(verifyRequestOrigin({ ...forged, origin: 'https://app.example.evil.example' })).toBe(
      false,
    );

    expect(verifyFetchSite({ method: 'POST', secFetchSite: 'cross-site' })).toBe(false);
    expect(verifyFetchSite({ method: 'POST', secFetchSite: undefined })).toBe(false);

    // The attacker's page can send the victim's cookies but cannot read the
    // token cookie, so it cannot echo it in the header.
    const token = createCsrfToken(secret, 'victim-session');

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: null,
        binding: 'victim-session',
        secrets: [secret],
      }),
    ).toBe(false);
  });

  it("refuses a token taken from the attacker's own session", () => {
    const attackers = createCsrfToken(secret, 'attacker-session');

    expect(
      verifyCsrfToken({
        cookieToken: attackers,
        headerToken: attackers,
        binding: 'victim-session',
        secrets: [secret],
      }),
    ).toBe(false);
  });

  it('refuses a token signed with a secret that was rotated out', () => {
    const old = new TextEncoder().encode('old-secret-old-secret-old-secret');
    const token = createCsrfToken(old, 'victim-session');

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding: 'victim-session',
        secrets: [secret],
      }),
    ).toBe(false);
  });

  it('accepts the same-origin request the app itself makes', () => {
    const token = createCsrfToken(secret, 'victim-session');

    expect(
      verifyRequestOrigin({
        method: 'POST',
        origin: 'https://app.example',
        allowedOrigins: ALLOWED,
      }),
    ).toBe(true);

    expect(verifyFetchSite({ method: 'POST', secFetchSite: 'same-origin' })).toBe(true);

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding: 'victim-session',
        secrets: [secret],
      }),
    ).toBe(true);
  });

  it('sets the session cookie SameSite=Lax by default, so a cross-site POST carries no session', async () => {
    const env = setup();
    const { token } = await env.signedInUser(EMAIL);

    expect(token).toMatch(/^[0-9a-f]{64}$/u);

    const login = await env.auth.login({
      email: EMAIL,
      password: 'correct horse battery',
      meta: { ip: '203.0.113.7' },
    });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login failed');

    expect(login.value.session.cookie.attributes.sameSite).toBe('lax');
  });
});
