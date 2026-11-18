// Email verification links through a `@Public()` Nest route, with the core's
// `linkWithoutSession` on: the guard resolves the caller's session on a public
// route too, so a link for one account opened while signed in as another is
// refused, and a link opened with no session verifies without signing anyone in.
import { afterEach, describe, expect, it } from 'vitest';
import {
  AccountController,
  boot,
  Browser,
  EMAIL,
  VerificationController,
  type Booted,
} from './support';

const EVE = 'eve@example.com';
const PASSWORD = 'correct horse battery staple';

describe('verify email links through a public Nest route', () => {
  let env: Booted;

  afterEach(async () => {
    await env.app.close();
  });

  async function start() {
    env = await boot({
      controllers: [AccountController, VerificationController],
      emailVerification: { kind: 'link', linkWithoutSession: true },
    });

    await env.auth.register({ email: EVE, password: PASSWORD, meta: { ip: '203.0.113.2' } });
    await env.auth.flush();

    const mail = env.mailer.sent.find((m) => m.type === 'verify-email' && m.to === EMAIL);
    const token = (mail?.type === 'verify-email' ? (mail.url ?? '') : '').split('#')[1] ?? '';
    const verified = async () => (await env.stores.users.findById(env.userId))?.emailVerified;

    return { token, verified };
  }

  it("refuses a token for one account inside another account's session", async () => {
    const { token, verified } = await start();
    const eve = new Browser(env.app, '198.51.100.9');

    await eve.signIn(EVE, PASSWORD);
    const refused = await eve.send('POST', '/api/verify-email-link', { token });

    expect(refused.status).toBe(401);
    expect(refused.body).toEqual({ error: { code: 'session_expired' } });
    expect(await verified()).toBe(false);

    // Left unspent: the owner can still open it.
    const owner = new Browser(env.app);

    await owner.send('GET', '/api/health');
    const accepted = await owner.send('POST', '/api/verify-email-link', { token });

    expect(accepted.body).toEqual({ verified: true, signedIn: false });
    expect(await verified()).toBe(true);
  });

  it('verifies a token opened without a session and signs nobody in', async () => {
    const { token, verified } = await start();
    const browser = new Browser(env.app);

    await browser.send('GET', '/api/health');
    const result = await browser.send('POST', '/api/verify-email-link', { token });

    expect(result.status).toBe(201);
    expect(result.body).toEqual({ verified: true, signedIn: false });
    expect(browser.cookies.has('session')).toBe(false);
    expect(await verified()).toBe(true);
  });
});
