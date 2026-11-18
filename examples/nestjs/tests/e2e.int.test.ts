// The example end to end on real Redis and PostgreSQL: register, sign in,
// read the account, a role granted and taken away, rotation, fresh auth and
// signing out.
import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrisma } from '../src/db';
import { bootApp, Browser } from './support';

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'];

if ((!databaseUrl || !redisUrl) && process.env['AUTH_REQUIRE_SERVICES'] === '1') {
  throw new Error('DATABASE_URL and REDIS_URL are required when AUTH_REQUIRE_SERVICES=1');
}

describe.skipIf(!databaseUrl || !redisUrl)('NestJS example end to end', () => {
  const prisma = createPrisma(databaseUrl ?? '');
  const email = `ada-${randomUUID()}@example.com`;
  const password = 'correct horse battery staple';
  let app: INestApplication;
  let prefix = '';

  beforeAll(async () => {
    const booted = await bootApp({ DATABASE_URL: databaseUrl, REDIS_URL: redisUrl });

    app = booted.app;
    prefix = booted.config.redisPrefix;
  });

  afterAll(async () => {
    const { Redis } = await import('ioredis');
    const redis = new Redis(redisUrl ?? '');
    const keys = await redis.keys(`${prefix}*`);

    if (keys.length) await redis.del(...keys);

    await redis.quit();
    await prisma.user.deleteMany({ where: { email } });
    await prisma.$disconnect();
    await app.close();
  });

  it('registers, signs in, reads the account, rotates and signs out', async () => {
    const browser = new Browser(app);

    expect(await browser.send('GET', '/auth/session')).toEqual({
      status: 200,
      body: { user: null },
    });

    expect(browser.cookies.has('csrf')).toBe(true);

    expect((await browser.send('POST', '/auth/register', { email, password })).status).toBe(201);

    const login = await browser.send('POST', '/auth/login', { email, password });

    expect(login.status).toBe(201);
    expect(login.body['csrfToken']).toBe(browser.cookies.get('csrf'));

    const me = await browser.send('GET', '/account/me');

    expect(me).toMatchObject({ status: 200, body: { user: { email } } });

    const sessions = await browser.send('GET', '/account/sessions');

    const listed = sessions.body['sessions'] as { handle: string; current: boolean }[];

    // One session, named by its public handle, never its store key.
    expect(listed.map((s) => s.current)).toEqual([true]);
    expect(listed[0]?.handle).toMatch(/^[\w-]{43}$/u);
    expect(listed[0]).not.toHaveProperty('id');

    const unknown = await browser.send('POST', '/account/sessions/revoke', { handle: 'nope' });

    expect(unknown).toMatchObject({ status: 201, body: { revoked: false } });

    const before = browser.cookies.get('session');

    expect((await browser.send('POST', '/account/reauthenticate', { password })).status).toBe(201);
    expect(browser.cookies.get('session')).not.toBe(before);
    expect((await browser.send('GET', '/account/me')).status).toBe(200);

    expect((await browser.send('POST', '/auth/logout')).status).toBe(201);
    expect((await browser.send('GET', '/account/me')).status).toBe(401);
  });

  // One write per call: each role change is its own step the next request must see.
  const setRole = (role: string) => prisma.user.update({ where: { email }, data: { role } });

  it('reads the role from the database on every request', async () => {
    const browser = new Browser(app);

    await browser.send('GET', '/health');
    await browser.send('POST', '/auth/login', { email, password });

    expect((await browser.send('GET', '/admin')).status).toBe(403);

    await setRole('admin');

    expect((await browser.send('GET', '/admin')).status).toBe(200);

    await setRole('member');

    expect((await browser.send('GET', '/admin')).status).toBe(403);
  });

  it('changes the password behind a fresh proof and keeps this browser signed in', async () => {
    const browser = new Browser(app);
    const newPassword = 'a different horse battery staple';

    await browser.send('GET', '/health');
    await browser.send('POST', '/auth/login', { email, password });

    const changed = await browser.send('POST', '/account/password', {
      currentPassword: password,
      newPassword,
    });

    expect(changed.status).toBe(201);
    expect((await browser.send('GET', '/account/me')).status).toBe(200);
  });
});
