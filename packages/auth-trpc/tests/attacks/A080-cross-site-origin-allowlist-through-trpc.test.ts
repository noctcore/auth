// A080: riding the cross-site origin allowlist against a tRPC endpoint.
//
// An app that serves a desktop shell from its own scheme lists the shell's
// origin in `csrf.crossSiteOrigins`, so the shell's `Sec-Fetch-Site:
// cross-site` mutations pass. An attacker tries to ride that opening: from a
// web origin that is not listed, from one that only looks like the shell's,
// from the shell's origin without a token, or by counting on the CSRF
// cookies staying `Lax` while the session cookie is `None` (so the shell can
// never send them back and the app is pushed to weaken the check).
//
// Stopped by: auth-trpc src/context.ts and src/options.ts: only an exact
//   listed origin passes the Origin and fetch-metadata checks as cross-site,
//   the double-submit token is still required, a wildcard entry is refused
//   when the context is created, and every cookie the adapter sets takes the
//   session cookie's SameSite through the core's `resolveSameSite`.
// Learn: CSRF (/auth/learn/csrf/); Cookies and desktop shells; core A008
import { AuthConfigError } from '@noctcore/auth';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuthContext } from '../../src';
import {
  boot,
  Browser,
  CSRF_SECRET,
  EMAIL,
  failure,
  makeAuth,
  ORIGIN,
  PASSWORD,
  type Booted,
} from '../support';

const SHELL = 'app://desktop';
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

describe('A080: riding the cross-site origin allowlist against a tRPC endpoint', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
    booted = undefined;
  });

  it('serves the listed shell origin end to end, with every cookie SameSite=None', async () => {
    booted = await boot(withShell);
    const shell = new Browser(booted);

    shell.override = crossSite(SHELL);
    await shell.client.health.query();

    expect(sameSiteOf(shell.lastSetCookies, '__Host-presession')).toBe('None');
    expect(sameSiteOf(shell.lastSetCookies, '__Host-csrf')).toBe('None');

    await shell.client.login.mutate({ email: EMAIL, password: PASSWORD });

    expect(sameSiteOf(shell.lastSetCookies, '__Host-session')).toBe('None');
    expect(sameSiteOf(shell.lastSetCookies, '__Host-csrf')).toBe('None');
    await expect(shell.client.echo.mutate({ note: 'x' })).resolves.toBeDefined();

    await shell.client.logout.mutate();

    expect(sameSiteOf(shell.lastSetCookies, '__Host-presession')).toBe('None');
    expect(sameSiteOf(shell.lastSetCookies, '__Host-csrf')).toBe('None');
  });

  it('refuses a cross-site origin that is not listed, or only looks like the shell', async () => {
    booted = await boot(withShell);
    const browser = new Browser(booted);

    await browser.signIn();

    for (const origin of [
      'https://evil.example',
      'app://desktop.evil.example',
      'app://desktop:8080',
      'evil://desktop',
      'null',
      null,
    ]) {
      browser.override = crossSite(origin);

      expect(
        (await failure(browser.client.echo.mutate({ note: 'x' }))).message,
        String(origin),
      ).toBe('forbidden');
    }
  });

  it("still needs the token from the listed origin: no token, or another browser's, is refused", async () => {
    booted = await boot(withShell);
    const shell = new Browser(booted);
    const attacker = new Browser(booted, '198.51.100.66');

    shell.override = crossSite(SHELL);
    attacker.override = crossSite(SHELL);
    await shell.signIn();
    await attacker.client.health.query();

    for (const token of [null, 'deadbeef.cafe', attacker.csrf]) {
      shell.override = { ...crossSite(SHELL), 'x-csrf-token': token };
      expect((await failure(shell.client.echo.mutate({ note: 'x' }))).message).toBe('forbidden');
    }
  });

  it('keeps cross-site refused by default, even for an origin on allowedOrigins', async () => {
    booted = await boot({
      cookie,
      options: { csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN, SHELL] } },
    });

    const shell = new Browser(booted);

    shell.override = crossSite(SHELL);
    await shell.client.health.query();

    expect((await failure(shell.client.logout.mutate())).message).toBe('forbidden');
  });

  it('gives the web app Lax cookies, and clears a refused session with the same SameSite', async () => {
    booted = await boot(withShell);
    const web = new Browser(booted);

    await web.client.health.query();

    expect(sameSiteOf(web.lastSetCookies, '__Host-presession')).toBe('Lax');
    expect(sameSiteOf(web.lastSetCookies, '__Host-csrf')).toBe('Lax');

    const stale = new Browser(booted);

    stale.override = { ...crossSite(SHELL), cookie: '__Host-session=not-a-live-session' };
    await stale.client.health.query();

    expect(stale.lastSetCookies.some((line) => line.startsWith('__Host-session=;'))).toBe(true);
    expect(sameSiteOf(stale.lastSetCookies, '__Host-session')).toBe('None');
  });

  it('refuses a wildcard or malformed crossSiteOrigins entry when the context is created', () => {
    const { auth } = makeAuth();

    for (const entry of ['*', 'app://*', 'https://*.example.com', 'null', 'not an origin']) {
      expect(
        () =>
          createAuthContext({
            auth,
            trustedHops: 0,
            csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], crossSiteOrigins: [entry] },
          }),
        entry,
      ).toThrow(AuthConfigError);
    }
  });
});
