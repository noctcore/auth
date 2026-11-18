// Email verification links through a public tRPC procedure, with the core's
// `linkWithoutSession` on: the context resolves the caller's session on a
// public procedure too, so a link for one account opened while signed in as
// another is refused, and a link opened with no session verifies without
// signing anyone in.
import { afterEach, describe, expect, it } from 'vitest';
import { boot, Browser, EMAIL, failure, type Booted } from './support';

const EVE = 'eve@example.com';
const PASSWORD = 'correct horse battery staple';

describe.each(['fetch', 'node'] as const)('verify email links on the %s adapter', (transport) => {
  let env: Booted;

  afterEach(async () => {
    await env.close();
  });

  async function start() {
    env = await boot({ transport, emailVerification: { kind: 'link', linkWithoutSession: true } });

    await env.auth.register({ email: EVE, password: PASSWORD, meta: { ip: '203.0.113.2' } });
    await env.auth.flush();

    const mail = env.mailer.sent.find((m) => m.type === 'verify-email' && m.to === EMAIL);
    const token = (mail?.type === 'verify-email' ? (mail.url ?? '') : '').split('#')[1] ?? '';

    return {
      token,
      verified: async () => (await env.stores.users.findById(env.userId))?.emailVerified,
    };
  }

  it("refuses a token for one account inside another account's session", async () => {
    const { token, verified } = await start();
    const eve = new Browser(env, '198.51.100.9');

    await eve.signIn(EVE, PASSWORD);
    const error = await failure(eve.client.verifyEmailLink.mutate({ token }));

    expect(error.data?.auth).toEqual({ code: 'session_expired' });
    expect(await verified()).toBe(false);

    // Left unspent: the owner can still open it.
    const owner = new Browser(env);

    await owner.client.health.query();

    await expect(owner.client.verifyEmailLink.mutate({ token })).resolves.toMatchObject({
      verified: true,
      signedIn: false,
    });

    expect(await verified()).toBe(true);
  });

  it('verifies a token opened without a session and signs nobody in', async () => {
    const { token, verified } = await start();
    const browser = new Browser(env);

    await browser.client.health.query();
    const result = await browser.client.verifyEmailLink.mutate({ token });

    expect(result).toEqual({ verified: true, signedIn: false });
    expect(browser.cookies.has('session')).toBe(false);
    expect(await verified()).toBe(true);
  });
});
