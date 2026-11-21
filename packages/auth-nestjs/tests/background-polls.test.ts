// Background polls: the `touch` option keeps requests the page makes on its
// own from counting as activity, so the core's idle timeout still ends a
// session nobody is using. The session is still validated once per request,
// and the CSRF verdict and the guard's decisions do not move.
import { AuthConfigError } from '@noctcore/auth';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthModuleOptions, TouchRequest } from '../src';
import { resolveOptions } from '../src/options';
import { sessionState } from '../src/request';
import { Browser, boot, CSRF_SECRET, makeAuth, ORIGIN, type Booted } from './support';

const MINUTE = 60 * 1000;

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

async function start(touch?: AuthModuleOptions['touch']): Promise<Browser> {
  t = await boot(touch === undefined ? {} : { options: { touch } });

  const browser = new Browser(t.app);

  await browser.signIn();

  return browser;
}

/** The stored last-active time, read without touching. */
async function lastActive(browser: Browser): Promise<number> {
  const result = await t.auth.validateRequest({
    token: browser.cookies.get('session') ?? '',
    touch: false,
  });

  if (!result.ok) throw new Error('the session is gone');

  return result.value.lastActiveAt;
}

describe('background polls', () => {
  it('touches on every request by default', async () => {
    const browser = await start();
    const before = await lastActive(browser);

    t.clock.advance(2 * MINUTE);
    expect((await browser.send('GET', '/api/me')).status).toBe(200);

    expect(await lastActive(browser)).toBe(before + 2 * MINUTE);
  });

  it('answers a request the predicate marks passive with the session, and leaves it untouched', async () => {
    const seen: TouchRequest[] = [];

    const browser = await start((request) => {
      seen.push(request);

      return request.path !== '/api/me';
    });

    const before = await lastActive(browser);

    t.clock.advance(2 * MINUTE);

    const answer = await browser.send('GET', '/api/me?since=1');

    expect(answer.status).toBe(200);
    expect(answer.body['user']).toBe(t.userId);
    expect(await lastActive(browser)).toBe(before);
    expect(seen.at(-1)).toMatchObject({ method: 'GET', path: '/api/me' });
    expect(seen.at(-1)?.headers.origin).toBe(ORIGIN);

    await browser.send('GET', '/api/whoami');
    expect(await lastActive(browser)).toBe(before + 2 * MINUTE);
  });

  it('lets an idle session expire while only passive requests arrive', async () => {
    const browser = await start((request) => request.path !== '/api/whoami');

    // The idle timeout is 30 minutes; a poll every 5 never extends it.
    for (let minute = 5; minute < 30; minute += 5) {
      t.clock.advance(5 * MINUTE);
      expect((await browser.send('GET', '/api/whoami')).body['user']).toBe(t.userId);
    }

    t.clock.advance(6 * MINUTE);

    expect((await browser.send('GET', '/api/whoami')).body['user']).toBeNull();
    expect((await browser.send('GET', '/api/me')).status).toBe(401);
  });

  it('touches on no request with touch: false', async () => {
    const browser = await start(false);
    const before = await lastActive(browser);

    t.clock.advance(2 * MINUTE);
    expect((await browser.send('GET', '/api/me')).status).toBe(200);

    expect(await lastActive(browser)).toBe(before);
  });

  it('keeps the CSRF verdict and the guard decisions whatever the option says', async () => {
    const browser = await start(() => false);

    // An unsafe request without its token is still refused, and passes with it.
    expect((await browser.send('POST', '/api/echo', {}, { 'x-csrf-token': 'forged' })).status).toBe(
      403,
    );

    expect((await browser.send('POST', '/api/echo', { a: 1 })).status).toBe(201);

    // A role the user does not hold is still refused.
    expect((await browser.send('GET', '/api/admin')).status).toBe(403);

    // A caller with no session is still refused a closed route.
    expect((await new Browser(t.app).send('GET', '/api/me')).status).toBe(401);
  });
});

describe('the touch option', () => {
  const options = (touch: unknown): AuthModuleOptions => ({
    auth: makeAuth().auth,
    trustedHops: 0,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    touch: touch as boolean,
  });

  it('refuses anything but a boolean or a function at boot', () => {
    for (const touch of ['no', 0, null, {}]) {
      expect(() => resolveOptions(options(touch))).toThrow(AuthConfigError);
    }
  });

  it('asks the predicate once per request, with GET for a request without a method', async () => {
    const predicate = vi.fn(() => true);
    const resolved = resolveOptions(options(predicate));
    const req = { headers: { cookie: 'session=abc' }, url: '/poll' };

    await sessionState(req, resolved);
    await sessionState(req, resolved);

    expect(predicate).toHaveBeenCalledTimes(1);
    expect(predicate).toHaveBeenCalledWith({ method: 'GET', path: '/poll', headers: req.headers });
  });
});
