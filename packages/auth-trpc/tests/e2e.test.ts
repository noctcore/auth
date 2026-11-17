// End to end: a real tRPC client against a real tRPC server, on the fetch
// adapter and on the standalone Node adapter, through the same router.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { boot, Browser, EMAIL, failure, PASSWORD, type Booted } from './support';

describe.each(['fetch', 'node'] as const)('tRPC on the %s adapter', (transport) => {
  let env: Booted;

  afterEach(async () => {
    await env.close();
  });

  const start = async (roles?: Map<string, readonly string[]>) => {
    env = await boot({ transport, ...(roles ? { roles } : {}) });

    return new Browser(env);
  };

  it('hands out a pre-session and a CSRF cookie on the first query', async () => {
    const browser = await start();

    await expect(browser.client.health.query()).resolves.toEqual({ ok: true });
    expect([...browser.cookies.keys()].sort()).toEqual(['csrf', 'presession']);

    // A second query with a current token sets nothing new.
    await browser.client.health.query();
    expect(browser.lastSetCookies).toEqual([]);
  });

  it('refuses a protected procedure without a session', async () => {
    const browser = await start();
    const error = await failure(browser.client.me.query());

    expect(error.data?.code).toBe('UNAUTHORIZED');
    expect(error.message).toBe('session_expired');
    expect(error.data?.auth).toEqual({ code: 'session_expired' });
  });

  it('signs in, reads the user through the output schema, and lists the session', async () => {
    const browser = await start();
    const signedIn = await browser.signIn();

    expect(signedIn).toMatchObject({ kind: 'session' });
    expect(browser.cookies.get('session')).toBeTruthy();
    expect(browser.cookies.get('device')).toBeTruthy();
    expect(browser.csrf).toBe((signedIn as { csrfToken: string }).csrfToken);

    await expect(browser.client.me.query()).resolves.toEqual({
      id: env.userId,
      email: EMAIL,
      emailVerified: false,
    });

    await expect(browser.client.whoami.query()).resolves.toEqual({ user: env.userId });
    await expect(browser.client.sessions.query()).resolves.toHaveLength(1);
    await expect(browser.client.meta.query()).resolves.toMatchObject({ ip: '198.51.100.7' });
  });

  it('refuses a mutation without the CSRF token, with a foreign Origin or a cross-site fetch', async () => {
    const browser = await start();

    await browser.signIn();

    for (const override of [
      { 'x-csrf-token': null },
      { origin: 'https://evil.example' },
      { 'sec-fetch-site': 'cross-site' },
    ]) {
      browser.override = override;

      const error = await failure(browser.client.echo.mutate({ note: 'hi' }));

      expect(error.data?.code).toBe('FORBIDDEN');
      expect(error.message).toBe('forbidden');
    }

    browser.override = {};
    await expect(browser.client.echo.mutate({ note: 'hi' })).resolves.toEqual({ note: 'hi' });
  });

  it('refuses a public sign-in without the CSRF token (login CSRF)', async () => {
    const browser = await start();

    await browser.client.health.query();
    browser.override = { 'x-csrf-token': null };

    const error = await failure(browser.client.login.mutate({ email: EMAIL, password: PASSWORD }));

    expect(error.message).toBe('forbidden');
    expect(browser.cookies.has('session')).toBe(false);
  });

  it('refuses an expired session and clears its cookie', async () => {
    const browser = await start();

    await browser.signIn();
    env.clock.advance(31 * 24 * 60 * 60 * 1000);

    const error = await failure(browser.client.me.query());

    expect(error.message).toBe('session_expired');
    expect(browser.cookies.has('session')).toBe(false);
  });

  it('refuses a revoked session, and a session whose user was deleted', async () => {
    const browser = await start();

    await browser.signIn();

    const revoked = await browser.client.revokeAll.mutate();

    expect(revoked.csrfToken).toBe(browser.csrf);

    expect(browser.cookies.has('session')).toBe(false);
    expect((await failure(browser.client.me.query())).message).toBe('session_expired');

    const again = new Browser(env);

    await again.signIn();
    vi.spyOn(env.stores.users, 'findById').mockResolvedValue(null);
    expect((await failure(again.client.me.query())).message).toBe('session_expired');
  });

  it('refreshes the session and CSRF cookies on rotation', async () => {
    const browser = await start();

    await browser.signIn();

    const before = { session: browser.cookies.get('session'), csrf: browser.csrf };
    const rotated = await browser.client.reauthenticate.mutate({ password: PASSWORD });

    expect(browser.cookies.get('session')).not.toBe(before.session);
    expect(browser.csrf).not.toBe(before.csrf);
    expect(browser.csrf).toBe(rotated.csrfToken);
    await expect(browser.client.echo.mutate({ note: 'ok' })).resolves.toEqual({ note: 'ok' });
  });

  it('signs out through the core and starts a fresh pre-session', async () => {
    const browser = await start();

    await browser.signIn();

    const before = browser.cookies.get('presession');
    const out = await browser.client.logout.mutate();

    expect(browser.cookies.has('session')).toBe(false);
    expect(browser.cookies.get('presession')).not.toBe(before);
    expect(browser.csrf).toBe(out.csrfToken);
    expect((await failure(browser.client.me.query())).message).toBe('session_expired');
  });

  it('asks for a fresh proof, and a role read on every call', async () => {
    const roles = new Map<string, readonly string[]>();
    const browser = await start(roles);

    await browser.signIn();
    await expect(browser.client.sensitive.mutate()).resolves.toEqual({ done: true });

    env.clock.advance(2 * 60 * 1000);

    expect((await failure(browser.client.verySensitive.mutate())).message).toBe(
      'fresh_auth_required',
    );

    expect((await failure(browser.client.admin.query())).data?.code).toBe('FORBIDDEN');
    roles.set(env.userId, ['admin']);
    await expect(browser.client.admin.query()).resolves.toEqual({ admin: true });
  });

  it('rate limits by the client IP and says when to retry', async () => {
    const browser = await start();

    await browser.client.limited.query();
    await browser.client.limited.query();

    const error = await failure(browser.client.limited.query());

    expect(error.data?.code).toBe('TOO_MANY_REQUESTS');
    expect(error.data?.auth).toEqual({ code: 'rate_limited', retryAfterSeconds: 60 });

    // Still refused after the first refusal (which alone is audited).
    expect((await failure(browser.client.limited.query())).message).toBe('rate_limited');

    // Another client IP has its own budget.
    await expect(new Browser(env, '198.51.100.8').client.limited.query()).resolves.toEqual({
      pong: true,
    });
  });

  it('answers a thrown error with internal and no message or stack', async () => {
    const browser = await start();
    const error = await failure(browser.client.boom.query());

    expect(error.message).toBe('internal');
    expect(JSON.stringify(error.shape)).not.toContain('4f2a');
    expect(error.data).not.toHaveProperty('stack');
  });

  it('answers a store failure while resolving the session with internal', async () => {
    const browser = await start();

    await browser.signIn();
    vi.spyOn(env.stores.sessions, 'get').mockRejectedValue(new Error('redis down at key s:4f2a'));

    const error = await failure(browser.client.me.query());

    expect(error.message).toBe('internal');
    expect(JSON.stringify(error.shape)).not.toContain('4f2a');
  });
});
