// The module in a real Nest app: signing in and out, the closed default, the
// CSRF layer, expired and revoked sessions, rotation, roles and fresh auth.
import { afterEach, describe, expect, it } from 'vitest';
import { Browser, boot, EMAIL, PASSWORD, type Booted } from './support';

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

describe('signing in and reading the session', () => {
  it('hands out a pre-session and a CSRF cookie on the first visit, then signs in', async () => {
    t = await boot();
    const browser = new Browser(t.app);
    const visit = await browser.send('GET', '/api/health');

    expect(visit.status).toBe(200);
    expect(browser.cookies.has('presession')).toBe(true);
    expect(browser.cookies.has('csrf')).toBe(true);

    const login = await browser.send('POST', '/api/login', { email: EMAIL, password: PASSWORD });

    expect(login.status).toBe(201);
    expect(login.body['csrfToken']).toBe(browser.csrf);
    expect(browser.cookies.has('session')).toBe(true);
    expect(browser.cookies.has('device')).toBe(true);

    const me = await browser.send('GET', '/api/me');

    expect(me).toMatchObject({
      status: 200,
      body: { user: t.userId, email: EMAIL, session: true },
    });
  });

  it('keeps the CSRF cookie it already handed out while the binding is the same', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    const again = await browser.send('GET', '/api/me');

    expect(again.setCookies).toEqual([]);
  });

  it('works the same when the options come from forRootAsync', async () => {
    t = await boot({ async: true });
    const browser = new Browser(t.app);

    expect((await browser.signIn()).status).toBe(201);
    expect((await browser.send('GET', '/api/me')).status).toBe(200);
  });

  it('gives a public route the user when there is one, and null when there is not', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    expect((await browser.send('GET', '/api/whoami')).body).toEqual({ user: null });

    await browser.signIn();

    expect((await browser.send('GET', '/api/whoami')).body).toEqual({ user: t.userId });
  });

  it('builds RequestMeta from the trusted hops, the user agent and the origin', async () => {
    t = await boot();
    const browser = new Browser(t.app, '192.0.2.44');

    await browser.signIn();
    const meta = await browser.send('GET', '/api/meta', undefined, { 'user-agent': 'TestBrowser' });

    expect(meta.body).toEqual({
      ip: '192.0.2.44',
      userAgent: 'TestBrowser',
      origin: 'http://app.test',
    });

    const bare = await browser.send('GET', '/api/meta', undefined, {
      origin: null,
      'user-agent': null,
    });

    expect(bare.body).toEqual({ ip: '192.0.2.44', userAgent: '' });
  });
});

describe('unauthenticated access', () => {
  it('refuses a protected route without a session, with a fixed body', async () => {
    t = await boot();
    const answer = await new Browser(t.app).send('GET', '/api/me');

    expect(answer).toMatchObject({ status: 401, body: { error: { code: 'session_expired' } } });
  });

  it('refuses a made-up session cookie and clears it', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    browser.cookies.set('session', 'not-a-real-token');
    const answer = await browser.send('GET', '/api/me');

    expect(answer.status).toBe(401);

    expect(
      answer.setCookies.some((c) => c.startsWith('session=;') && c.includes('Max-Age=0')),
    ).toBe(true);

    expect(browser.cookies.has('session')).toBe(false);
  });

  it('lets public routes and whole public controllers through', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    expect((await browser.send('GET', '/api/health')).status).toBe(200);
    expect((await browser.send('GET', '/open')).status).toBe(200);
  });
});

describe('expired and revoked sessions', () => {
  it('refuses a session past its idle timeout', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    t.clock.advance(25 * 60 * 60 * 1000);

    expect((await browser.send('GET', '/api/me')).status).toBe(401);
  });

  it('refuses a session revoked by signing out everywhere', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    const stolen = new Map(browser.cookies);

    await t.auth.context.revokeAllSessions(t.userId, 'revoke-all');
    const thief = new Browser(t.app);

    for (const [name, value] of stolen) thief.cookies.set(name, value);

    expect((await thief.send('GET', '/api/me')).status).toBe(401);
  });

  it('signs out a session whose user no longer exists', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    const users = t.auth.context.users as { findById: (id: string) => Promise<unknown> };

    users.findById = async () => null;

    expect((await browser.send('GET', '/api/me')).status).toBe(401);
  });

  it('signs out: clears the session cookie and starts a new pre-session', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    const token = browser.cookies.get('session') ?? '';
    const out = await browser.send('POST', '/api/logout');

    expect(out.status).toBe(201);
    expect(out.body['csrfToken']).toBe(browser.csrf);
    expect(browser.cookies.has('session')).toBe(false);
    expect(browser.cookies.has('presession')).toBe(true);
    expect((await t.auth.validateRequest({ token })).ok).toBe(false);
    expect((await browser.send('GET', '/api/me')).status).toBe(401);
  });
});

describe('rotation', () => {
  it('sets the new session cookie and a CSRF token bound to it, and the old token stops working', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    const oldSession = browser.cookies.get('session') ?? '';
    const oldCsrf = browser.csrf;
    const rotated = await browser.send('POST', '/api/reauthenticate', { password: PASSWORD });

    expect(rotated.status).toBe(201);
    expect(browser.cookies.get('session')).not.toBe(oldSession);
    expect(browser.csrf).not.toBe(oldCsrf);
    expect(rotated.body['csrfToken']).toBe(browser.csrf);
    expect((await t.auth.validateRequest({ token: oldSession })).ok).toBe(false);

    expect((await browser.send('POST', '/api/echo', { a: 1 })).status).toBe(201);

    const stale = await browser.send('POST', '/api/echo', { a: 1 }, { 'x-csrf-token': oldCsrf });

    expect(stale.status).toBe(403);
  });

  it('hands a fresh CSRF cookie to a page whose session changed elsewhere', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.send('GET', '/api/health');
    const preSessionCsrf = browser.csrf;

    // Sign in without picking up the cookies the login answer set for CSRF.
    const login = await browser.send('POST', '/api/login', { email: EMAIL, password: PASSWORD });

    browser.cookies.set('csrf', preSessionCsrf);
    expect(login.status).toBe(201);

    const next = await browser.send('GET', '/api/me');

    expect(next.setCookies.some((c) => c.startsWith('csrf='))).toBe(true);
    expect(browser.csrf).not.toBe(preSessionCsrf);
  });
});

describe('roles', () => {
  it('lets a user with the role through and refuses one without it', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();

    expect((await browser.send('GET', '/api/admin')).status).toBe(403);

    t.roles.set(t.userId, ['admin']);

    expect((await browser.send('GET', '/api/admin')).body).toEqual({ admin: true });
  });

  it('needs the controller role and the handler role both', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();
    t.roles.set(t.userId, ['staff']);

    expect((await browser.send('GET', '/staff')).status).toBe(200);
    expect((await browser.send('GET', '/staff/payroll')).status).toBe(403);

    t.roles.set(t.userId, ['admin']);

    expect((await browser.send('GET', '/staff/payroll')).status).toBe(200);
  });

  it('accepts roles from an async function', async () => {
    t = await boot({ options: { roles: async () => ['admin'] } });
    const browser = new Browser(t.app);

    await browser.signIn();

    expect((await browser.send('GET', '/api/admin')).status).toBe(200);
  });
});

describe('fresh authentication', () => {
  it('lets a recent proof through and refuses one older than freshAuthAge', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();

    expect((await browser.send('POST', '/api/sensitive')).status).toBe(201);

    t.clock.advance(11 * 60 * 1000);

    expect((await browser.send('POST', '/api/sensitive')).body).toEqual({
      error: { code: 'fresh_auth_required' },
    });

    await browser.send('POST', '/api/reauthenticate', { password: PASSWORD });

    expect((await browser.send('POST', '/api/sensitive')).status).toBe(201);
  });

  it('applies a stricter maxAge on top of freshAuthAge', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.signIn();

    expect((await browser.send('POST', '/api/very-sensitive')).status).toBe(201);

    t.clock.advance(2 * 60 * 1000);

    expect((await browser.send('POST', '/api/very-sensitive')).status).toBe(403);
    expect((await browser.send('POST', '/api/sensitive')).status).toBe(201);
  });
});
