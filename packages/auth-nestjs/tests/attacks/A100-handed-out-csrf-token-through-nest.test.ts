// A100: using a CSRF token read from the token route of a Nest app for
// another session or pre-session.
//
// A desktop shell on its own scheme cannot read the API's `__Host-csrf`
// cookie, so it reads the token from a public GET route
// (`SessionCookies.csrfToken`). An attacker who can call that route too (any
// client can) tries to make the token worth something elsewhere: their own
// pre-session's token in the victim's browser, one session's token with
// another session, a pre-session token after the sign-in it led to, the
// token alone without its cookie, or a page on an origin the app never
// allowed that reads the token with the victim's cookies (a permissive
// credentialed CORS setup lets it) and replays it.
//
// Stopped by: auth-nestjs src/session-cookies.ts and src/csrf.middleware.ts:
//   the route returns only the token the middleware set or kept as the
//   cookie, bound to the request's own session or pre-session, and every
//   unsafe request still needs that cookie next to the header and a binding
//   that matches its own session (the core's `verifyCsrfToken`). An unsafe
//   request from an origin outside the allowlist is refused on its Origin and
//   `Sec-Fetch-Site` before the token is even compared, so CORS settings do
//   not decide it.
// Learn: CSRF (/auth/learn/csrf/); Cookies and desktop shells; core A008, A079
import { afterEach, describe, expect, it } from 'vitest';
import { boot, Browser, CSRF_SECRET, EMAIL, ORIGIN, PASSWORD, type Booted } from '../support';

const SHELL = 'app://desktop';
const FORBIDDEN = { error: { code: 'forbidden' } };
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

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

async function tokenOf(browser: Browser): Promise<string> {
  const answer = await browser.send('GET', '/api/csrf-token', undefined, crossSite);

  return String(answer.body['csrfToken']);
}

const post = (browser: Browser, path: string, token: string | null, body: object = {}) =>
  browser.send('POST', path, body, { ...crossSite, 'x-csrf-token': token });

describe('A100: a handed-out CSRF token used for another session or pre-session on Nest', () => {
  it("refuses a pre-session token read by another browser in the victim's", async () => {
    t = await boot(withShell);
    const victim = new Browser(t.app);
    const attacker = new Browser(t.app);

    await tokenOf(victim);
    const stolen = await tokenOf(attacker);
    const login = { email: EMAIL, password: PASSWORD };

    expect(await post(victim, '/api/login', stolen, login)).toMatchObject({
      status: 403,
      body: FORBIDDEN,
    });

    // Even with the cookie planted next to it: the binding is the victim's pre-session.
    victim.cookies.set('__Host-csrf', stolen);

    expect(await post(victim, '/api/login', stolen, login)).toMatchObject({
      status: 403,
      body: FORBIDDEN,
    });
  });

  it("refuses one session's token with another session of the same user", async () => {
    t = await boot(withShell);
    const first = new Browser(t.app);
    const second = new Browser(t.app);

    for (const browser of [first, second]) {
      const login = await post(browser, '/api/login', await tokenOf(browser), {
        email: EMAIL,
        password: PASSWORD,
      });

      expect(login.status).toBe(201);
    }

    const firstToken = await tokenOf(first);

    expect((await post(first, '/api/echo', firstToken)).status).toBe(201);

    expect(await post(second, '/api/echo', firstToken)).toMatchObject({
      status: 403,
      body: FORBIDDEN,
    });

    second.cookies.set('__Host-csrf', firstToken);

    expect(await post(second, '/api/echo', firstToken)).toMatchObject({
      status: 403,
      body: FORBIDDEN,
    });
  });

  it('refuses a pre-session token once the browser has signed in', async () => {
    t = await boot(withShell);
    const shell = new Browser(t.app);
    const preSessionToken = await tokenOf(shell);

    const login = await post(shell, '/api/login', preSessionToken, {
      email: EMAIL,
      password: PASSWORD,
    });

    expect(login.status).toBe(201);
    shell.cookies.set('__Host-csrf', preSessionToken);

    expect(await post(shell, '/api/echo', preSessionToken)).toMatchObject({
      status: 403,
      body: FORBIDDEN,
    });
  });

  it('refuses the token without its cookie', async () => {
    t = await boot(withShell);
    const shell = new Browser(t.app);
    const token = await tokenOf(shell);

    shell.cookies.delete('__Host-csrf');

    expect(
      await post(shell, '/api/login', token, { email: EMAIL, password: PASSWORD }),
    ).toMatchObject({ status: 403, body: FORBIDDEN });
  });

  it('refuses a token read by a page on an origin the app does not allow', async () => {
    t = await boot(withShell);
    const victim = new Browser(t.app);
    const evil = { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' };

    // The page reads the token with the victim's cookies, as a permissive
    // `cors({ origin: true, credentials: true })` would let it.
    const read = await victim.send('GET', '/api/csrf-token', undefined, evil);
    const token = String(read.body['csrfToken']);

    expect(token).toBe(victim.cookies.get('__Host-csrf'));

    expect(
      await victim.send(
        'POST',
        '/api/login',
        { email: EMAIL, password: PASSWORD },
        { ...evil, 'x-csrf-token': token },
      ),
    ).toMatchObject({ status: 403, body: FORBIDDEN });
  });
});
