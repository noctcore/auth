// Handing the CSRF token to a client that cannot read the API's cookies (a
// desktop shell on its own scheme, a web app on another origin): the browser
// engine still stores and sends the cookies, but the client's script never
// sees them, so it reads the token from `SessionCookies.csrfToken` on a
// public GET route and echoes it in the header.
import { afterEach, describe, expect, it } from 'vitest';
import { boot, Browser, CSRF_SECRET, EMAIL, ORIGIN, PASSWORD, type Booted } from './support';

const SHELL = 'app://desktop';
const crossSite = { origin: SHELL, 'sec-fetch-site': 'cross-site' };

const withShell = {
  cookie: {
    secure: true,
    sameSite: (origin: string | undefined) => (origin === SHELL ? 'none' : 'lax'),
  },
  options: {
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], crossSiteOrigins: [SHELL] },
  },
} as const;

/** The value a response's `Set-Cookie` gives `name`, or undefined when it sets none. */
const setValue = (lines: readonly string[], name: string) =>
  lines
    .find((line) => line.startsWith(`${name}=`))
    ?.split(';')[0]
    ?.slice(name.length + 1);

/**
 * A shell whose browser engine keeps the cookies (the jar) while its script
 * holds only the token it was handed, never the cookie's value.
 */
class Shell {
  readonly engine: Browser;
  token = '';

  constructor(t: Booted) {
    this.engine = new Browser(t.app);
  }

  async fetchToken() {
    const answer = await this.engine.send('GET', '/api/csrf-token', undefined, crossSite);

    this.token = String(answer.body['csrfToken']);

    return answer;
  }

  send(method: 'GET' | 'POST', path: string, body?: object) {
    return this.engine.send(method, path, body, { ...crossSite, 'x-csrf-token': this.token });
  }

  /** A restart: the script's memory and the browser-session cookies are gone, a persistent session stays. */
  restart(): void {
    this.token = '';
    this.engine.cookies.delete('__Host-csrf');
    this.engine.cookies.delete('__Host-presession');
  }
}

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

describe('SessionCookies.csrfToken', () => {
  it('lets a client with no cookie access sign in, and get a token for its session after a restart', async () => {
    t = await boot(withShell);
    const shell = new Shell(t);

    await shell.fetchToken();
    expect(shell.token).toMatch(/\./u);

    const login = await shell.send('POST', '/api/login', { email: EMAIL, password: PASSWORD });

    expect(login.status).toBe(201);
    shell.token = String(login.body['csrfToken']);
    expect((await shell.send('POST', '/api/echo', {})).status).toBe(201);

    shell.restart();
    expect((await shell.send('POST', '/api/echo', {})).status).toBe(403);

    await shell.fetchToken();

    expect((await shell.send('POST', '/api/echo', {})).status).toBe(201);
    expect((await shell.send('GET', '/api/me')).body['user']).toBe(t.userId);
  });

  it('returns exactly the csrf cookie the response sets or keeps, with no-store', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    // No cookie yet: the response mints the pre-session and the cookie.
    const first = await browser.send('GET', '/api/csrf-token');

    expect(first.status).toBe(200);
    expect(first.headers['cache-control']).toBe('no-store');
    expect(setValue(first.setCookies, 'presession')).toBeDefined();
    expect(first.body['csrfToken']).toBe(setValue(first.setCookies, 'csrf'));

    // A current cookie: kept, and returned as it is.
    const second = await browser.send('GET', '/api/csrf-token');

    expect(second.setCookies).toEqual([]);
    expect(second.body['csrfToken']).toBe(browser.csrf);

    // Signed in with a cookie still bound to the pre-session: a new one is set.
    await browser.send('POST', '/api/login', { email: EMAIL, password: PASSWORD });
    browser.cookies.set('csrf', String(first.body['csrfToken']));

    const third = await browser.send('GET', '/api/csrf-token');

    expect(setValue(third.setCookies, 'csrf')).toBe(third.body['csrfToken']);
    expect(third.body['csrfToken']).not.toBe(first.body['csrfToken']);
  });

  it('mints nothing on an exempt path, and refuses an unsafe method', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    const exempt = await browser.send('GET', '/open/webhook');

    expect(exempt.status).toBe(500);
    expect(exempt.setCookies).toEqual([]);
    expect(exempt.body['csrfToken']).toBeUndefined();

    await browser.send('GET', '/api/health');

    const unsafe = await browser.send('POST', '/api/csrf-token', {});

    expect(unsafe.status).toBe(500);
    expect(unsafe.body['csrfToken']).toBeUndefined();
  });
});
