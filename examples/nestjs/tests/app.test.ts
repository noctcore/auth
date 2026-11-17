// The compile test: boots the whole AppModule, so a provider Nest cannot
// resolve fails in CI, not at deploy. Then walks every route and fails on one
// that answers without a session and is not marked @Public(). No Redis or
// Postgres needed: both clients connect lazily, and a request without a
// session cookie never reaches a store.
import type { INestApplication } from '@nestjs/common';
import { describeRoutes } from '@noctcore/auth-nestjs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bootApp, Browser } from './support';

// The routes meant to be reachable without a session. Adding one is a
// decision a reviewer should see in the diff.
const PUBLIC_ROUTES = [
  'GET /health',
  'GET /auth/session',
  'POST /auth/register',
  'POST /auth/login',
  'POST /auth/logout',
];

describe('AppModule', () => {
  let app: INestApplication;

  beforeAll(async () => {
    ({ app } = await bootApp());
  });

  afterAll(async () => {
    await app.close();
  });

  it('boots with every provider resolved', () => {
    expect(describeRoutes(app).length).toBeGreaterThan(0);
  });

  it('opens exactly the routes on the public list', () => {
    const open = describeRoutes(app)
      .filter((route) => route.public)
      .map((route) => `${route.method} ${route.path}`)
      .sort();

    expect(open).toEqual([...PUBLIC_ROUTES].sort());
  });

  it('refuses every other route without a session', async () => {
    const closed = describeRoutes(app).filter((route) => !route.public);

    expect(closed.length).toBeGreaterThan(0);

    for (const route of closed) {
      const browser = new Browser(app);

      // A page visit first, so an unsafe request carries a valid CSRF token
      // and the guard, not the CSRF layer, is what answers.
      await browser.send('GET', '/health');
      const answer = await browser.send(route.method === 'GET' ? 'GET' : 'POST', route.path, {});

      expect(answer, `${route.method} ${route.path}`).toMatchObject({
        status: 401,
        body: { error: { code: 'session_expired' } },
      });
    }
  });

  it('refuses to boot in production without TRUST_PROXY', async () => {
    await expect(bootApp({ NODE_ENV: 'production', TRUST_PROXY: undefined })).rejects.toThrow(
      /TRUST_PROXY/u,
    );
  });
});
