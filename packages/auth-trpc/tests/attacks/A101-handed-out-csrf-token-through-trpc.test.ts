// A101: using a CSRF token read from `ctx.auth.csrfToken()` on a tRPC
// endpoint for another session or pre-session.
//
// A desktop shell on its own scheme cannot read the API's `__Host-csrf`
// cookie, so it reads the token from a public query that returns
// `ctx.auth.csrfToken()`. An attacker who can call that query too (any
// client can) tries to make the token worth something elsewhere: their own
// pre-session's token in the victim's browser, one session's token with
// another session, a pre-session token after the sign-in it led to, or the
// token alone without its cookie.
//
// Stopped by: auth-trpc src/context.ts: `csrfToken()` returns only the token
//   the context set or kept as the cookie, bound to the request's own session
//   or pre-session, and every mutation still needs that cookie next to the
//   header and a binding that matches its own session (the core's
//   `verifyCsrfToken`).
// Learn: CSRF (/auth/learn/csrf/); Cookies and desktop shells; core A008, A080
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
} from '../support';

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

/** A shell that sends `token` in the header, whatever its cookie jar holds. */
function sending(browser: Browser, token: string | null): Browser {
  browser.override = { origin: SHELL, 'sec-fetch-site': 'cross-site', 'x-csrf-token': token };

  return browser;
}

async function tokenOf(browser: Browser): Promise<string> {
  return (await sending(browser, null).client.csrfToken.query()).csrfToken;
}

async function signIn(browser: Browser, token: string) {
  return sending(browser, token).client.login.mutate({ email: EMAIL, password: PASSWORD });
}

const refusal = async (call: Promise<unknown>) => (await failure(call)).message;

describe('A101: a handed-out CSRF token used for another session or pre-session on tRPC', () => {
  let env: Booted;

  afterEach(async () => {
    await env.close();
  });

  it("refuses a pre-session token read by another browser in the victim's", async () => {
    env = await boot(withShell);
    const victim = new Browser(env);
    const attacker = new Browser(env, '198.51.100.66');

    await tokenOf(victim);
    const stolen = await tokenOf(attacker);

    expect(await refusal(signIn(victim, stolen))).toBe('forbidden');

    // Even with the cookie planted next to it: the binding is the victim's pre-session.
    victim.cookies.set('__Host-csrf', stolen);
    expect(await refusal(signIn(victim, stolen))).toBe('forbidden');
  });

  it("refuses one session's token with another session of the same user", async () => {
    env = await boot(withShell);
    const first = new Browser(env);
    const second = new Browser(env, '198.51.100.66');

    for (const browser of [first, second]) {
      await expect(signIn(browser, await tokenOf(browser))).resolves.toMatchObject({
        kind: 'session',
      });
    }

    const firstToken = await tokenOf(first);

    await expect(sending(first, firstToken).client.echo.mutate({ note: 'x' })).resolves.toEqual({
      note: 'x',
    });

    expect(await refusal(sending(second, firstToken).client.echo.mutate({ note: 'x' }))).toBe(
      'forbidden',
    );

    second.cookies.set('__Host-csrf', firstToken);

    expect(await refusal(sending(second, firstToken).client.echo.mutate({ note: 'x' }))).toBe(
      'forbidden',
    );
  });

  it('refuses a pre-session token once the browser has signed in', async () => {
    env = await boot(withShell);
    const shell = new Browser(env);
    const preSessionToken = await tokenOf(shell);

    await expect(signIn(shell, preSessionToken)).resolves.toMatchObject({ kind: 'session' });
    shell.cookies.set('__Host-csrf', preSessionToken);

    expect(await refusal(sending(shell, preSessionToken).client.echo.mutate({ note: 'x' }))).toBe(
      'forbidden',
    );
  });

  it('refuses the token without its cookie', async () => {
    env = await boot(withShell);
    const shell = new Browser(env);
    const token = await tokenOf(shell);

    shell.cookies.delete('__Host-csrf');

    expect(await refusal(signIn(shell, token))).toBe('forbidden');
  });
});
