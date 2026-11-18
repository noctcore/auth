// A078: riding the cross-site origin allowlist against a Nest app.
//
// An app that serves a desktop shell from its own scheme lists the shell's
// origin in `csrf.crossSiteOrigins`, so the shell's `Sec-Fetch-Site:
// cross-site` requests pass. An attacker tries to ride that opening: from a
// web origin that is not listed, from one that only looks like the shell's,
// from the shell's origin without a token, or by counting on the CSRF
// cookies staying `Lax` while the session cookie is `None` (so the shell can
// never send them back and the app is pushed to weaken the check).
//
// Stopped by: auth-nestjs src/csrf.middleware.ts and src/options.ts: only an
//   exact listed origin passes the Origin and fetch-metadata checks as
//   cross-site, the double-submit token is still required, a wildcard entry
//   is refused at boot, and every cookie the module sets takes the session
//   cookie's SameSite through the core's `resolveSameSite`.
// Learn: CSRF (/auth/learn/csrf/); Cookies and desktop shells; core A008
import { afterEach, describe, expect, it } from 'vitest';
import { AuthConfigError } from '@noctcore/auth';
import { boot, Browser, CSRF_SECRET, ORIGIN, type Booted } from '../support';

const SHELL = 'app://desktop';
const FORBIDDEN = { error: { code: 'forbidden' } };
const crossSite = (origin: string | null) => ({ origin, 'sec-fetch-site': 'cross-site' });

/** The shell gets `None`, the web app keeps `Lax`, over Secure cookies. */
const cookie = {
  secure: true,
  sameSite: (origin: string | undefined) => (origin === SHELL ? 'none' : 'lax'),
} as const;

const withShell = {
  cookie,
  options: {
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], crossSiteOrigins: [SHELL] },
  },
};

const sameSiteOf = (lines: readonly string[], name: string) =>
  /SameSite=(\w+)/u.exec(lines.find((line) => line.startsWith(`${name}=`)) ?? '')?.[1];

let t: Booted | undefined;

afterEach(async () => {
  await t?.app.close();
  t = undefined;
});

describe('A078: riding the cross-site origin allowlist against a Nest app', () => {
  it('serves the listed shell origin end to end, with every cookie SameSite=None', async () => {
    t = await boot(withShell);
    const shell = new Browser(t.app);

    const visit = await shell.send('GET', '/api/health', undefined, crossSite(SHELL));

    expect(sameSiteOf(visit.setCookies, '__Host-presession')).toBe('None');
    expect(sameSiteOf(visit.setCookies, '__Host-csrf')).toBe('None');

    const login = await shell.send(
      'POST',
      '/api/login',
      { email: 'ada@example.com', password: 'correct horse battery staple' },
      crossSite(SHELL),
    );

    expect(login.status).toBe(201);
    expect(sameSiteOf(login.setCookies, '__Host-session')).toBe('None');
    expect(sameSiteOf(login.setCookies, '__Host-csrf')).toBe('None');
    expect((await shell.send('POST', '/api/echo', {}, crossSite(SHELL))).status).toBe(201);

    const logout = await shell.send('POST', '/api/logout', {}, crossSite(SHELL));

    expect(sameSiteOf(logout.setCookies, '__Host-presession')).toBe('None');
    expect(sameSiteOf(logout.setCookies, '__Host-csrf')).toBe('None');
  });

  it('refuses a cross-site origin that is not listed, or only looks like the shell', async () => {
    t = await boot(withShell);
    const browser = new Browser(t.app);

    await browser.signIn();

    for (const origin of [
      'https://evil.example',
      'app://desktop.evil.example',
      'app://desktop:8080',
      'evil://desktop',
      'null',
      null,
    ]) {
      expect(
        await browser.send('POST', '/api/echo', {}, crossSite(origin)),
        String(origin),
      ).toMatchObject({ status: 403, body: FORBIDDEN });
    }
  });

  it("still needs the token from the listed origin: no token, or another browser's, is refused", async () => {
    t = await boot(withShell);
    const shell = new Browser(t.app);
    const attacker = new Browser(t.app);

    await shell.send('GET', '/api/health', undefined, crossSite(SHELL));
    await attacker.send('GET', '/api/health', undefined, crossSite(SHELL));

    for (const token of [null, 'deadbeef.cafe', attacker.csrf]) {
      expect(
        await shell.send('POST', '/api/echo', {}, { ...crossSite(SHELL), 'x-csrf-token': token }),
      ).toMatchObject({ status: 403, body: FORBIDDEN });
    }
  });

  it('keeps cross-site refused by default, even for an origin on allowedOrigins', async () => {
    t = await boot({
      cookie,
      options: { csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN, SHELL] } },
    });

    const shell = new Browser(t.app);

    await shell.send('GET', '/api/health', undefined, crossSite(SHELL));

    expect(await shell.send('POST', '/api/echo', {}, crossSite(SHELL))).toMatchObject({
      status: 403,
      body: FORBIDDEN,
    });
  });

  it('gives the web app Lax cookies, and clears a refused session with the same SameSite', async () => {
    t = await boot(withShell);

    const web = await new Browser(t.app).send('GET', '/api/health');

    expect(sameSiteOf(web.setCookies, '__Host-presession')).toBe('Lax');
    expect(sameSiteOf(web.setCookies, '__Host-csrf')).toBe('Lax');

    const stale = await new Browser(t.app).send('GET', '/api/health', undefined, {
      ...crossSite(SHELL),
      cookie: '__Host-session=not-a-live-session',
    });

    expect(stale.setCookies.some((line) => line.startsWith('__Host-session=;'))).toBe(true);
    expect(sameSiteOf(stale.setCookies, '__Host-session')).toBe('None');
  });

  it('refuses a wildcard or malformed crossSiteOrigins entry at boot', async () => {
    for (const entry of ['*', 'app://*', 'https://*.example.com', 'null', 'not an origin']) {
      await expect(
        boot({
          options: {
            csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], crossSiteOrigins: [entry] },
          },
        }),
        entry,
      ).rejects.toThrow(AuthConfigError);
    }
  });
});
