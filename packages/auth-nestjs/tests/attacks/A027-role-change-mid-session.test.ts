// A027: keeping a role after it was taken away.
//
// An admin is demoted (or a user is removed) while signed in, and their open
// session keeps the old rights because the role was read once at sign-in and
// cached in the session, the cookie or a token.
//
// Stopped by: auth-nestjs src/session.guard.ts: the user is loaded from the
//   store on every request, and the module's `roles` function is called with
//   it on every request that needs a role, after the session check; nothing
//   about roles is stored in the cookie or the session.
// Learn: Build, "Use with NestJS" (/auth/build/nestjs/)
import { afterEach, describe, expect, it } from 'vitest';
import { boot, Browser, type Booted } from '../support';

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

describe('A027: keeping a role after it was taken away', () => {
  it('refuses the next request after a demotion, with the same session cookie', async () => {
    t = await boot();
    t.roles.set(t.userId, ['admin']);
    const browser = new Browser(t.app);

    await browser.signIn();
    const cookie = browser.cookies.get('session');

    expect((await browser.send('GET', '/api/admin')).status).toBe(200);

    t.roles.set(t.userId, []);

    expect(browser.cookies.get('session')).toBe(cookie);

    expect(await browser.send('GET', '/api/admin')).toMatchObject({
      status: 403,
      body: { error: { code: 'forbidden' } },
    });
  });

  it('grants a new role on the next request without signing in again', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();

    expect((await browser.send('GET', '/api/admin')).status).toBe(403);

    t.roles.set(t.userId, ['admin']);

    expect((await browser.send('GET', '/api/admin')).status).toBe(200);
  });

  it('checks the session before any role, so a role never stands in for one', async () => {
    t = await boot({ options: { roles: () => ['admin'] } });

    expect((await new Browser(t.app).send('GET', '/api/admin')).status).toBe(401);
  });
});
