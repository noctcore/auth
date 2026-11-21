// Handing the CSRF token to a client that cannot read the API's cookies (a
// desktop shell on its own scheme, a web app on another origin): the browser
// engine still stores and sends the cookies, but the client's script never
// sees them, so it reads the token from `ctx.auth.csrfToken()` in a public
// query and echoes it in the header.
import { afterEach, describe, expect, it } from 'vitest';
import {
  boot,
  Browser,
  CSRF_SECRET,
  EMAIL,
  failure,
  ORIGIN,
  PASSWORD,
  type Booted,
} from './support';

const SHELL = 'app://desktop';

const withShell = {
  cookie: {
    secure: true,
    sameSite: (origin: string | undefined) => (origin === SHELL ? 'none' : 'lax'),
  },
  options: {
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], crossSiteOrigins: [SHELL] },
  },
} as const;

/** The value the last response's `Set-Cookie` gave `name`, or undefined when it set none. */
const setValue = (browser: Browser, name: string) =>
  browser.lastSetCookies
    .find((line) => line.startsWith(`${name}=`))
    ?.split(';')[0]
    ?.slice(name.length + 1);

describe.each(['fetch', 'node'] as const)('ctx.auth.csrfToken on the %s adapter', (transport) => {
  let env: Booted;

  afterEach(async () => {
    await env.close();
  });

  it('lets a client with no cookie access sign in, and get a token for its session after a restart', async () => {
    env = await boot({ transport, ...withShell });

    // The engine keeps the cookies; the script holds only the token it was handed.
    const shell = new Browser(env);
    let token = '';

    const use = () => {
      shell.override = { origin: SHELL, 'sec-fetch-site': 'cross-site', 'x-csrf-token': token };
    };

    use();
    token = (await shell.client.csrfToken.query()).csrfToken;
    use();

    const login = await shell.client.login.mutate({ email: EMAIL, password: PASSWORD });

    token = (login as { csrfToken: string }).csrfToken;
    use();
    await expect(shell.client.echo.mutate({ note: 'hi' })).resolves.toEqual({ note: 'hi' });

    // A restart: the script's memory and the browser-session cookies are gone.
    token = '';
    use();
    shell.cookies.delete('__Host-csrf');
    shell.cookies.delete('__Host-presession');
    expect((await failure(shell.client.echo.mutate({ note: 'hi' }))).data?.code).toBe('FORBIDDEN');

    token = (await shell.client.csrfToken.query()).csrfToken;
    use();

    await expect(shell.client.echo.mutate({ note: 'hi' })).resolves.toEqual({ note: 'hi' });
    await expect(shell.client.whoami.query()).resolves.toEqual({ user: env.userId });
  });

  it('returns exactly the csrf cookie the response sets or keeps, with no-store', async () => {
    env = await boot({ transport });
    const browser = new Browser(env);

    // No cookie yet: the response mints the pre-session and the cookie.
    const first = await browser.client.csrfToken.query();

    expect(browser.lastHeaders.get('cache-control')).toBe('no-store');
    expect(setValue(browser, 'presession')).toBeDefined();
    expect(first.csrfToken).toBe(setValue(browser, 'csrf'));

    // A current cookie: kept, and returned as it is.
    const second = await browser.client.csrfToken.query();

    expect(browser.lastSetCookies).toEqual([]);
    expect(second.csrfToken).toBe(browser.csrf);

    // Signed in with a cookie still bound to the pre-session: a new one is set.
    await browser.client.login.mutate({ email: EMAIL, password: PASSWORD });
    browser.cookies.set('csrf', first.csrfToken);

    const third = await browser.client.csrfToken.query();

    expect(setValue(browser, 'csrf')).toBe(third.csrfToken);
    expect(third.csrfToken).not.toBe(first.csrfToken);
  });

  it('refuses a request with an unsafe method and a streamed batch, and leaves no-store off other queries', async () => {
    env = await boot({ transport });
    const browser = new Browser(env);

    await browser.client.health.query();
    expect(browser.lastHeaders.get('cache-control')).toBeNull();

    const unsafe = await failure(browser.client.csrfTokenByPost.mutate());

    expect(unsafe.message).toBe('internal');

    const streamed = new Browser(env, undefined, 'stream');

    streamed.cookies.set('csrf', browser.csrf);
    streamed.cookies.set('presession', browser.cookies.get('presession') ?? '');

    expect((await failure(streamed.client.csrfToken.query())).message).toBe('internal');
  });
});
