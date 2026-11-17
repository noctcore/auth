// A026: cross-site request forgery against a Nest app.
//
// A page on another site posts to the app with the user's cookies: with no
// Origin, with its own Origin, with a cross-site Sec-Fetch-Site, or with a
// CSRF token it obtained for another browser or session. A refusal that names
// the failed check helps the attacker tune the next try.
//
// Stopped by: auth-nestjs src/csrf.middleware.ts: before any guard, every
//   unsafe method needs an allowed Origin, Sec-Fetch-Site same-origin when
//   sent, and a double-submit token bound to this session or pre-session; a
//   refusal is a 403 with one fixed body, answered by the middleware itself.
// Learn: CSRF (/auth/learn/csrf/); core attack A008
import { afterEach, describe, expect, it } from 'vitest';
import { boot, Browser, ORIGIN, type Booted } from '../support';

const FORBIDDEN = { error: { code: 'forbidden' } };

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

describe('A026: cross-site request forgery against a Nest app', () => {
  it('refuses a missing, null or foreign Origin, signed in or not, with the same body', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    for (const signedIn of [false, true]) {
      if (signedIn) await browser.signIn();
      else await browser.send('GET', '/api/health');

      for (const origin of [null, 'null', 'https://evil.example', 'http://app.test.evil.example']) {
        const answer = await browser.send('POST', '/api/echo', { a: 1 }, { origin });

        expect(answer).toMatchObject({ status: 403, body: FORBIDDEN });
      }
    }
  });

  it('refuses a cross-site Sec-Fetch-Site even with an allowed Origin and a valid token', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();

    for (const site of ['cross-site', 'same-site', 'none']) {
      const answer = await browser.send('POST', '/api/echo', {}, { 'sec-fetch-site': site });

      expect(answer).toMatchObject({ status: 403, body: FORBIDDEN });
    }

    expect((await browser.send('POST', '/api/echo', {}, { 'sec-fetch-site': null })).status).toBe(
      201,
    );
  });

  it('accepts same-site only when the app opted in', async () => {
    t = await boot({
      options: {
        csrf: {
          secrets: ['csrf-secret-that-is-at-least-32-bytes-long'],
          allowedOrigins: [ORIGIN],
          allowSameSite: true,
        },
      },
    });

    const browser = new Browser(t.app);

    await browser.signIn();

    expect(
      (await browser.send('POST', '/api/echo', {}, { 'sec-fetch-site': 'same-site' })).status,
    ).toBe(201);
  });

  it("refuses a missing, mismatched, or another browser's token", async () => {
    t = await boot();
    const victim = new Browser(t.app);
    const attacker = new Browser(t.app);

    await victim.signIn();
    await attacker.send('GET', '/api/health');

    const cases: Record<string, string | null>[] = [
      { 'x-csrf-token': null },
      { 'x-csrf-token': 'deadbeef.cafe' },
      { 'x-csrf-token': attacker.csrf },
      {
        cookie: `session=${victim.cookies.get('session') ?? ''}; csrf=${attacker.csrf}`,
        'x-csrf-token': attacker.csrf,
      },
    ];

    for (const override of cases) {
      expect(await victim.send('POST', '/api/echo', {}, override)).toMatchObject({
        status: 403,
        body: FORBIDDEN,
      });
    }
  });

  it('refuses an unsafe request from a browser that never got a pre-session', async () => {
    t = await boot();

    const answer = await new Browser(t.app).send('POST', '/api/login', {
      email: 'a@b.c',
      password: 'x',
    });

    expect(answer).toMatchObject({ status: 403, body: FORBIDDEN });
  });

  it('checks public routes too, and skips only the exempt path, which mints nothing', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    expect((await browser.send('POST', '/open/webhook', {}, { origin: null })).status).toBe(201);
    expect(browser.cookies.size).toBe(0);

    await browser.send('GET', '/api/health');

    expect((await browser.send('POST', '/api/logout', {}, { origin: null })).status).toBe(403);
  });

  it('never exempts a safe method from the session check', async () => {
    t = await boot();

    expect(
      (await new Browser(t.app).send('GET', '/forgot', undefined, { origin: null })).status,
    ).toBe(401);
  });
});
