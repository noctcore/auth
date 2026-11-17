// A028: passing a fresh-auth check with a stale proof.
//
// Someone at an unlocked, long-signed-in browser reaches a sensitive action
// (changing the email, deleting the account) without proving the password
// again, or the client claims a recent sign-in through a header or the body.
//
// Stopped by: auth-nestjs src/session.guard.ts: @RequireFreshAuth() reads the
//   stored session's authenticatedAt through the core's requireFreshAuth, and
//   a route's own maxAge can only make the window shorter.
// Learn: Sessions and expiry (/auth/learn/sessions-and-expiry/)
import { afterEach, describe, expect, it } from 'vitest';
import { boot, Browser, type Booted } from '../support';

const MINUTE = 60 * 1000;

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

describe('A028: passing a fresh-auth check with a stale proof', () => {
  it('refuses a proof older than freshAuthAge, whatever the request claims', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    t.clock.advance(11 * MINUTE);

    const claimed = await browser.send(
      'POST',
      '/api/sensitive',
      { authenticatedAt: t.clock.now(), fresh: true },
      { 'x-authenticated-at': String(t.clock.now()), 'x-fresh-auth': '1' },
    );

    expect(claimed).toMatchObject({
      status: 403,
      body: { error: { code: 'fresh_auth_required' } },
    });
  });

  it('keeps refusing while the session is merely used, since use is not a proof', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();

    for (let i = 0; i < 12; i++) {
      t.clock.advance(MINUTE);
      await browser.send('GET', '/api/me');
    }

    expect((await browser.send('POST', '/api/sensitive')).status).toBe(403);
  });

  it('never lets a route maxAge stretch the configured window', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    t.clock.advance(2 * MINUTE);

    expect((await browser.send('POST', '/api/very-sensitive')).status).toBe(403);
  });
});
