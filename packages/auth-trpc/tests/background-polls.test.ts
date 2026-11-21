// Background polls: the `touch` option and the `touch: false` meta keep
// requests the page makes on its own from counting as activity, so the core's
// idle timeout still ends a session nobody is using. The session is still
// validated once per request, and the CSRF verdict and the guards do not move.
import { AuthConfigError } from '@noctcore/auth';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthContext, type AuthContextOptions } from '../src';
import { boot, Browser, CSRF_SECRET, failure, makeAuth, ORIGIN, type Booted } from './support';

const MINUTE = 60 * 1000;

describe.each(['fetch', 'node'] as const)('background polls on the %s adapter', (transport) => {
  let env: Booted;

  afterEach(async () => {
    await env.close();
  });

  const start = async (touch?: AuthContextOptions['touch'], link: 'plain' | 'batch' = 'plain') => {
    env = await boot({ transport, ...(touch === undefined ? {} : { options: { touch } }) });

    const browser = new Browser(env, undefined, link);

    await browser.signIn();

    return browser;
  };

  /** The stored last-active time, read without touching. */
  const lastActive = async (browser: Browser): Promise<number> => {
    const result = await env.auth.validateRequest({
      token: browser.cookies.get('session') ?? '',
      touch: false,
    });

    if (!result.ok) throw new Error('the session is gone');

    return result.value.lastActiveAt;
  };

  it('touches on every request by default', async () => {
    const browser = await start();
    const before = await lastActive(browser);

    env.clock.advance(2 * MINUTE);
    await browser.client.me.query();

    expect(await lastActive(browser)).toBe(before + 2 * MINUTE);
  });

  it('answers a procedure the predicate marks passive with the session, and leaves it untouched', async () => {
    const browser = await start((path) => path !== 'me');
    const before = await lastActive(browser);

    env.clock.advance(2 * MINUTE);

    await expect(browser.client.me.query()).resolves.toMatchObject({ id: env.userId });
    expect(await lastActive(browser)).toBe(before);

    await browser.client.whoami.query();
    expect(await lastActive(browser)).toBe(before + 2 * MINUTE);
  });

  it('leaves the session untouched for a procedure whose meta says touch: false', async () => {
    const browser = await start();
    const before = await lastActive(browser);

    env.clock.advance(2 * MINUTE);

    await expect(browser.client.poll.query()).resolves.toEqual({ user: env.userId });
    expect(await lastActive(browser)).toBe(before);
  });

  it('lets an idle session expire while only passive procedures are called', async () => {
    const browser = await start();

    // The idle timeout is 30 minutes; a poll every 5 never extends it.
    for (let minute = 5; minute < 30; minute += 5) {
      env.clock.advance(5 * MINUTE);
      await expect(browser.client.poll.query()).resolves.toEqual({ user: env.userId });
    }

    env.clock.advance(6 * MINUTE);

    await expect(browser.client.poll.query()).resolves.toEqual({ user: null });
    expect((await failure(browser.client.me.query())).message).toBe('session_expired');
  });

  it('touches a batch when any of its procedures is active', async () => {
    const browser = await start(undefined, 'batch');
    const before = await lastActive(browser);

    env.clock.advance(2 * MINUTE);
    await Promise.all([browser.client.poll.query(), browser.client.poll.query()]);
    expect(await lastActive(browser)).toBe(before);

    await Promise.all([browser.client.poll.query(), browser.client.me.query()]);
    expect(await lastActive(browser)).toBe(before + 2 * MINUTE);
  });

  it('touches on no request with touch: false', async () => {
    const browser = await start(false);
    const before = await lastActive(browser);

    env.clock.advance(2 * MINUTE);
    await browser.client.me.query();

    expect(await lastActive(browser)).toBe(before);
  });

  it('keeps the CSRF verdict and the guards whatever the option says', async () => {
    const browser = await start(() => false);

    // A mutation without its token is still refused, and passes with it.
    browser.override = { 'x-csrf-token': 'forged' };

    expect((await failure(browser.client.echo.mutate({ note: 'hi' }))).data?.code).toBe(
      'FORBIDDEN',
    );

    browser.override = {};
    await expect(browser.client.echo.mutate({ note: 'hi' })).resolves.toEqual({ note: 'hi' });

    // A role the user does not hold is still refused.
    expect((await failure(browser.client.admin.query())).data?.code).toBe('FORBIDDEN');

    // A caller with no session is still refused a protected procedure.
    const stranger = new Browser(env);

    expect((await failure(stranger.client.me.query())).data?.code).toBe('UNAUTHORIZED');
  });
});

describe('the touch option', () => {
  const base = (touch: unknown): AuthContextOptions => ({
    auth: makeAuth().auth,
    trustedHops: 0,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    touch: touch as boolean,
  });

  it('refuses anything but a boolean or a function at boot', () => {
    for (const touch of ['no', 0, null, {}]) {
      expect(() => createAuthContext(base(touch))).toThrow(AuthConfigError);
    }
  });

  it('touches when the adapter names no call, and asks the predicate about an unknown path', async () => {
    const options = base((path: string) => path !== 'poll');
    const validate = vi.spyOn(options.auth, 'validateRequest');
    const context = createAuthContext(options);
    const req = new Request(ORIGIN, { headers: { cookie: 'session=abc' } });

    await context.fetch({ req, resHeaders: new Headers() });

    await context.fetch({
      req,
      resHeaders: new Headers(),
      info: { calls: [{ path: 'poll', procedure: null }] },
    });

    await context.fetch({
      req,
      resHeaders: new Headers(),
      info: { calls: [{ path: 'other', procedure: {} }] },
    });

    expect(validate.mock.calls.map(([input]) => input.touch)).toEqual([true, false, true]);
  });
});
