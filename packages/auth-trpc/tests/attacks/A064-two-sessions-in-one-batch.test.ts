// A064: minting a session no browser holds, through a tRPC batch.
//
// `ctx.auth` is built once per HTTP request and shared by every procedure of
// a batch. With two cookie-writing procedures in one batch (two sign-ins, or
// a sign-in and a rotation), both core flows would run and both would write a
// session cookie. The browser keeps the last one, and the session from the
// other call stays valid in the store until it expires or is revoked: a live
// session that no browser holds.
//
// Stopped by: auth-trpc src/middlewares.ts (`writesCookies`, and
//   `WritesCookiesMiddleware` on nestjs-trpc, claim the request's one
//   cookie-writer slot; a second claim in the same request is refused before
//   its procedure runs) and src/context.ts (as a backstop, a second
//   `setSession`, `signOut` or `clearSession` in one request throws before
//   writing anything).
// Learn: Build: Use with tRPC (/auth/build/trpc/)
import { afterEach, describe, expect, it, vi } from 'vitest';
import { boot, Browser, EMAIL, PASSWORD, type Booted } from '../support';

describe.each(['fetch', 'node'] as const)('A064 two sessions in one batch (%s)', (transport) => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('runs the first sign-in of a batch and refuses the second before its flow runs', async () => {
    booted = await boot({ transport });

    const browser = new Browser(booted, '198.51.100.7', 'batch');

    await browser.client.health.query();

    const login = vi.spyOn(booted.auth, 'login');

    const [first, second] = await Promise.allSettled([
      browser.client.login.mutate({ email: EMAIL, password: PASSWORD }),
      browser.client.login.mutate({ email: EMAIL, password: PASSWORD }),
    ]);

    expect(first.status).toBe('fulfilled');
    expect(second.status === 'rejected' && (second.reason as Error).message).toBe('internal');
    expect(login).toHaveBeenCalledTimes(1);

    // One session in the store, and it is the one the browser holds.
    expect(await booted.stores.sessions.listByUser(booted.userId)).toHaveLength(1);
    await expect(browser.client.me.query()).resolves.toMatchObject({ email: EMAIL });
  });

  it('runs one of a rotation and a sign-out batched together, never both', async () => {
    booted = await boot({ transport });

    const browser = new Browser(booted, '198.51.100.7', 'batch');

    await browser.signIn();

    const reauthenticate = vi.spyOn(booted.auth, 'reauthenticate');
    const logout = vi.spyOn(booted.auth, 'logout');

    // The slot goes to whichever procedure reaches `writesCookies` first, which
    // is not always the first in the batch (a session lookup can delay one).
    const results = await Promise.allSettled([
      browser.client.reauthenticate.mutate({ password: PASSWORD }),
      browser.client.logout.mutate(),
    ]);

    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(reauthenticate.mock.calls.length + logout.mock.calls.length).toBe(1);

    // Whichever ran, the store agrees with the browser: a rotated session it
    // holds, or no session at all.
    const rotated = results[0].status === 'fulfilled';
    const live = await booted.stores.sessions.listByUser(booted.userId);

    const signedIn = await browser.client.me.query().then(
      () => true,
      () => false,
    );

    expect(live).toHaveLength(rotated ? 1 : 0);
    expect(signedIn).toBe(rotated);
  });

  it('lets one cookie writer share a batch with other procedures, and each request have its own', async () => {
    booted = await boot({ transport });

    const browser = new Browser(booted, '198.51.100.7', 'batch');

    await browser.client.health.query();

    const [, signedIn, who] = await Promise.all([
      browser.client.health.query(),
      browser.client.login.mutate({ email: EMAIL, password: PASSWORD }),
      browser.client.health.query(),
    ]);

    expect(signedIn).toMatchObject({ kind: 'session' });
    expect(who).toEqual({ ok: true });

    // A separate request gets its own slot.
    const rotated = await browser.client.reauthenticate.mutate({ password: PASSWORD });

    // The answer carries the CSRF token of the rotated session, now in the browser.
    expect(rotated.csrfToken).toBe(browser.csrf);
  });
});
