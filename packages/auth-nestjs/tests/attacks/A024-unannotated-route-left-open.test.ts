// A024: a route left open because nobody marked it.
//
// A new controller ships without a guard (or with the guard on some routes
// and not others), and anyone can call it. Or a guard trusts a user id the
// client put in a header or the body.
//
// Stopped by: auth-nestjs src/session.guard.ts: SessionGuard is registered
//   globally by AuthModule with no switch to turn it off, and refuses every
//   route without @Public(); the user comes from the stored session only.
//   src/routes.ts: describeRoutes lists every route with its rule for a test.
// Learn: Build, "Use with NestJS" (/auth/build/nestjs/)
import { afterEach, describe, expect, it } from 'vitest';
import { describeRoutes } from '../../src';
import { boot, Browser, type Booted } from '../support';

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

describe('A024: a route left open because nobody marked it', () => {
  it('refuses every route without @Public() when there is no session, found by walking them all', async () => {
    t = await boot();
    const routes = describeRoutes(t.app);

    expect(routes.length).toBeGreaterThan(10);

    for (const route of routes) {
      const browser = new Browser(t.app);

      // A page visit first, so unsafe requests carry a valid CSRF token and
      // the guard, not the CSRF layer, is what answers.
      await browser.send('GET', '/api/health');
      const method = route.method === 'GET' ? 'GET' : 'POST';
      const answer = await browser.send(method, route.path, method === 'GET' ? undefined : {});
      const label = `${route.method} ${route.path}`;
      const code = (answer.body['error'] as { code?: string } | undefined)?.code;

      // A public route may refuse for its own reasons (a wrong password); only
      // the guard answers 401 with `session_expired`.
      expect(answer.status === 401 && code === 'session_expired', label).toBe(!route.public);
    }
  });

  it('lists the rule of each route: open, roles, fresh auth', async () => {
    t = await boot();
    const routes = describeRoutes(t.app);

    const find = (path: string, method = 'GET') =>
      routes.find((route) => route.path === path && route.method === method);

    expect(find('/forgot')).toMatchObject({ public: false, controller: 'ForgottenController' });
    expect(find('/open')).toMatchObject({ public: true });
    expect(find('/api/health')).toMatchObject({ public: true, handler: 'health' });
    expect(find('/staff/payroll')?.roles).toEqual([['admin'], ['staff', 'admin']]);
    expect(find('/api/sensitive', 'POST')).toMatchObject({ freshAuth: true, public: false });
  });

  it('never takes the user from a header or the body', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.send('GET', '/api/health');

    const forged = await browser.send(
      'POST',
      '/api/echo',
      { userId: t.userId, user: { id: t.userId } },
      { 'x-user-id': t.userId, authorization: `Bearer ${t.userId}` },
    );

    expect(forged.status).toBe(401);

    expect(
      (await browser.send('GET', '/api/whoami', undefined, { 'x-user-id': t.userId })).body,
    ).toEqual({
      user: null,
    });
  });
});
