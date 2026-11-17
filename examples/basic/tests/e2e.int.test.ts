import type { AddressInfo } from 'node:net';
import { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { recordingMailer } from '@noctcore/auth/testing';
import { createApp } from '../src/app';
import { createPrisma } from '../src/db';

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'];

if ((!databaseUrl || !redisUrl) && process.env['AUTH_REQUIRE_SERVICES'] === '1') {
  throw new Error('DATABASE_URL and REDIS_URL are required when AUTH_REQUIRE_SERVICES=1');
}

/** A browser-ish client: keeps cookies, sends Origin, Sec-Fetch-Site and the CSRF header. */
class Browser {
  readonly cookies = new Map<string, string>();
  csrf = '';

  constructor(
    private readonly base: string,
    private readonly origin: string,
    private readonly ip: string,
  ) {}

  async request(
    method: string,
    path: string,
    body?: unknown,
    override: Record<string, string | null> = {},
  ) {
    const headers: Record<string, string> = {
      origin: this.origin,
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': this.csrf,
      'x-forwarded-for': this.ip,
      cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '),
    };

    if (body !== undefined) headers['content-type'] = 'application/json';

    for (const [key, value] of Object.entries(override)) {
      if (value === null) delete headers[key];
      else headers[key] = value;
    }

    const response = await fetch(`${this.base}${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });

    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split(';');
      const [name, ...rest] = (pair ?? '').split('=');
      const value = decodeURIComponent(rest.join('='));

      if (!name) continue;
      if (attributes.some((a) => a.trim().toLowerCase() === 'max-age=0')) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }

    const json = (await response.json()) as Record<string, unknown>;

    if (typeof json['csrfToken'] === 'string') this.csrf = json['csrfToken'];

    return { status: response.status, json };
  }
}

describe.skipIf(!databaseUrl || !redisUrl)('example app end to end', () => {
  const prisma = createPrisma(databaseUrl ?? '');
  const redis = new Redis(redisUrl ?? '');
  const mailer = recordingMailer();
  const prefix = `e2e-${Date.now()}:`;
  let base = '';
  let close: () => Promise<void> = async () => undefined;
  const origin = 'http://app.test';
  const email = `ada-${Date.now()}@example.com`;
  const password = 'correct horse battery staple';
  const teammates: string[] = [];
  const orgs: string[] = [];

  /** A new user, signed in, with its id. */
  async function teammate(ip: string) {
    const address = `team-${teammates.length}-${Date.now()}@example.com`;
    const browser = new Browser(base, origin, ip);

    teammates.push(address);
    await browser.request('GET', '/api/csrf');
    await browser.request('POST', '/api/register', { email: address, password });
    await browser.request('POST', '/api/login', { email: address, password });

    const me = await browser.request('GET', '/api/me');

    return { browser, id: (me.json['user'] as { id: string }).id };
  }

  beforeAll(async () => {
    const { server } = createApp({
      prisma,
      redis,
      mailer,
      origin,
      secret: 'e2e-secret-that-is-at-least-32-bytes!',
      csrfSecret: 'e2e-csrf-secret-at-least-32-bytes-long',
      secureCookies: false,
      redisPrefix: prefix,
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = () => new Promise((resolve) => server.close(() => resolve()));
  });

  afterAll(async () => {
    await close();
    const keys = await redis.keys(`${prefix}*`);

    if (keys.length) await redis.del(...keys);

    await prisma.$transaction([
      prisma.user.deleteMany({ where: { email: { in: [email, ...teammates] } } }),
      prisma.authMember.deleteMany({ where: { scope: { in: orgs } } }),
      prisma.authMemberScope.deleteMany({ where: { scope: { in: orgs } } }),
    ]);

    await redis.quit();
    await prisma.$disconnect();
  });

  it('registers, signs in, verifies the address, reads the account and signs out', async () => {
    const browser = new Browser(base, origin, '203.0.113.10');

    expect((await browser.request('GET', '/api/csrf')).status).toBe(200);
    expect(browser.cookies.has('csrf')).toBe(true);

    expect(await browser.request('POST', '/api/register', { email, password })).toEqual({
      status: 202,
      json: { status: 'check-your-email' },
    });

    // Sign-up answers before it writes the code and hands the mail over.
    const code = await vi.waitFor(() => {
      const sent = mailer.last('verify-email')?.code;

      expect(sent).toMatch(/^\d{8}$/u);

      return sent;
    });

    const login = await browser.request('POST', '/api/login', { email, password });

    expect(login.status).toBe(200);
    expect(browser.cookies.has('session')).toBe(true);
    const firstSession = browser.cookies.get('session');

    const before = await browser.request('GET', '/api/me');

    expect(before.json['user']).toMatchObject({ email, emailVerified: false });

    const verified = await browser.request('POST', '/api/verify-email', { code });

    expect(verified).toMatchObject({ status: 200, json: { verified: true } });
    expect(browser.cookies.get('session')).not.toBe(firstSession);

    const after = await browser.request('GET', '/api/me');

    expect(after.json['user']).toMatchObject({ email, emailVerified: true });
    expect((await browser.request('GET', '/api/sessions')).json['sessions']).toHaveLength(1);

    expect((await browser.request('POST', '/api/logout')).status).toBe(200);
    expect(browser.cookies.has('session')).toBe(false);

    expect(await browser.request('GET', '/api/me')).toEqual({
      status: 401,
      json: { error: { code: 'session_expired' } },
    });
  });

  it('answers a wrong password and an unknown address with the same body', async () => {
    const browser = new Browser(base, origin, '203.0.113.11');

    await browser.request('GET', '/api/csrf');

    const wrong = await browser.request('POST', '/api/login', {
      email,
      password: 'not the password at all',
    });

    const unknown = await browser.request('POST', '/api/login', {
      email: 'nobody@example.com',
      password,
    });

    expect(wrong).toEqual({ status: 401, json: { error: { code: 'invalid_credentials' } } });
    expect(unknown).toEqual(wrong);
  });

  it('refuses cross-site and token-less writes', async () => {
    const browser = new Browser(base, origin, '203.0.113.12');

    await browser.request('GET', '/api/csrf');
    const body = { email, password };
    const forbidden = { status: 403, json: { error: { code: 'forbidden' } } };

    expect(
      await browser.request('POST', '/api/login', body, { origin: 'https://evil.test' }),
    ).toEqual(forbidden);

    expect(await browser.request('POST', '/api/login', body, { origin: null })).toEqual(forbidden);

    expect(
      await browser.request('POST', '/api/login', body, { 'sec-fetch-site': 'cross-site' }),
    ).toEqual(forbidden);

    expect(await browser.request('POST', '/api/login', body, { 'x-csrf-token': null })).toEqual(
      forbidden,
    );

    expect(
      await browser.request('POST', '/api/login', body, { 'x-csrf-token': 'forged.token' }),
    ).toEqual(forbidden);
  });

  it('refuses a CSRF token minted for another session', async () => {
    const victim = new Browser(base, origin, '203.0.113.13');

    await victim.request('GET', '/api/csrf');
    await victim.request('POST', '/api/login', { email, password });
    const anonymousToken = new Browser(base, origin, '203.0.113.14');

    await anonymousToken.request('GET', '/api/csrf');
    // The attacker plants its own signed-out token pair in the victim's browser.
    victim.cookies.set('csrf', anonymousToken.cookies.get('csrf') ?? '');
    victim.csrf = anonymousToken.csrf;
    expect((await victim.request('POST', '/api/logout')).status).toBe(403);
  });

  it('binds signed-out CSRF tokens to a random per-browser pre-session id', async () => {
    const victim = new Browser(base, origin, '203.0.113.15');

    await victim.request('GET', '/api/csrf');
    expect(victim.cookies.get('presession')).toMatch(/^[0-9a-f]{32}$/u);
    const attacker = new Browser(base, origin, '203.0.113.16');

    await attacker.request('GET', '/api/csrf');
    // A token pair minted in another browser is useless in this one, even before sign-in.
    victim.cookies.set('csrf', attacker.cookies.get('csrf') ?? '');
    victim.csrf = attacker.csrf;
    expect((await victim.request('POST', '/api/login', { email, password })).status).toBe(403);
    // No pre-session cookie at all: refused too.
    const bare = new Browser(base, origin, '203.0.113.17');

    bare.cookies.set('csrf', attacker.cookies.get('csrf') ?? '');
    bare.csrf = attacker.csrf;
    expect((await bare.request('POST', '/api/login', { email, password })).status).toBe(403);
  });

  it('sets a trusted-device cookie on sign-in', async () => {
    const browser = new Browser(base, origin, '203.0.113.18');

    await browser.request('GET', '/api/csrf');
    expect((await browser.request('POST', '/api/login', { email, password })).status).toBe(200);
    expect(browser.cookies.get('device')).toMatch(/^[0-9a-f]{32}\.\d+\.\d+\.[0-9a-f]{64}$/u);
  });

  it('guards organisation roles: no self-target, no last admin, and revocation on change', async () => {
    const owner = await teammate('203.0.113.30');
    const bob = await teammate('203.0.113.31');
    const created = await owner.browser.request('POST', '/api/orgs');
    const orgId = String(created.json['orgId']);

    orgs.push(orgId);
    expect(created.status).toBe(201);

    const members = `/api/orgs/${orgId}/members`;

    expect(
      await owner.browser.request('POST', members, { userId: bob.id, role: 'member' }),
    ).toMatchObject({ status: 201 });

    // Nobody acts on themselves, and the last owner stays.
    expect(
      await owner.browser.request('POST', `${members}/${owner.id}`, { role: 'member' }),
    ).toEqual({ status: 403, json: { error: { code: 'self_target' } } });

    expect(await bob.browser.request('POST', `${members}/${owner.id}`, { role: 'member' })).toEqual(
      { status: 403, json: { error: { code: 'forbidden' } } },
    );

    // A promotion signs bob out everywhere; he signs in again under the new role.
    expect(
      await owner.browser.request('POST', `${members}/${bob.id}`, { role: 'admin' }),
    ).toMatchObject({ status: 200, json: { member: { role: 'admin' } } });

    expect((await bob.browser.request('GET', '/api/me')).status).toBe(401);

    await bob.browser.request('GET', '/api/csrf');

    expect(
      (
        await bob.browser.request('POST', '/api/login', {
          email: teammates[1],
          password,
        })
      ).status,
    ).toBe(200);

    // Two admins demoting each other at once, on Postgres: one wins, one is refused.
    const results = await Promise.all([
      owner.browser.request('POST', `${members}/${bob.id}`, { role: 'member' }),
      bob.browser.request('POST', `${members}/${owner.id}`, { role: 'member' }),
    ]);

    // The loser is refused by the last-admin guard (409), or, when the winner's
    // revocation lands first, already signed out when its request is validated (401).
    const statuses = results.map((r) => r.status).sort();

    expect(statuses[0]).toBe(200);
    expect([401, 409]).toContain(statuses[1]);

    const admins = await prisma.authMember.count({
      where: { scope: orgId, role: { in: ['owner', 'admin'] } },
    });

    expect(admins).toBe(1);
  });
});
