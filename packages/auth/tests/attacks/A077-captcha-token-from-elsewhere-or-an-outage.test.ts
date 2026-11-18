// A077: passing a captcha with a token solved elsewhere, or while the provider is down.
//
// A bot farm solves challenges once on a site of its own that shares the
// sitekey, or on a cheaper form of the same app, and replays the tokens at
// login; or it waits for (or causes) a provider outage, hoping the server lets
// requests through when the verifier cannot answer.
//
// Stopped by: http/turnstile.ts (the hostname the token was solved on and the
//   action it was solved for are checked when configured; an outage, a
//   timeout, a non-2xx answer and a malformed body are `unavailable`, never
//   `pass`; the `onResult` hook gets a frozen outcome and cannot change the
//   verdict), ports/provider-outcome.ts (a hook that throws or rejects is
//   logged, never passed on), core/auth-core.ts (`unavailable`
//   refuses the request like `reject`, before the door's rate limit and any
//   account work). Unit tests: tests/primitives/captcha.test.ts.
// Learn: Captcha (/auth/learn/captcha/)
import { describe, expect, it, vi } from 'vitest';

import { turnstile, type CaptchaVerifier } from '../../src';
import { countingHasher, EMAIL, meta, PASSWORD, recordStoreCalls, registered } from './support';

const HOST = 'app.example';

/** A siteverify stand-in that answers `body` with `status`, and counts its calls. */
function provider(body: unknown, status = 200) {
  return vi.fn(
    async () => new Response(JSON.stringify(body), { status }),
  ) as unknown as typeof fetch;
}

function verifier(siteverify: typeof fetch): CaptchaVerifier {
  return turnstile({
    secret: 'turnstile-test-secret',
    expectedHostnames: [HOST],
    checkAction: true,
    fetch: siteverify,
  });
}

/**
 * An app with a registered account and the given captcha, recording every
 * store call and password verify after the account exists. The account is
 * registered while the captcha passes, then the captcha under test takes over.
 */
async function app(captcha: CaptchaVerifier) {
  const counting = countingHasher();
  let current: CaptchaVerifier = { verify: async () => 'pass' };

  const env = await registered({
    captcha: { verify: (token, context) => current.verify(token, context) },
    password: { hasher: counting.hasher, breachCheck: false },
  });

  current = captcha;
  counting.verified.length = 0;

  const { calls } = recordStoreCalls(env.stores as never);

  return { ...env, calls, verified: counting.verified };
}

describe('A077: passing a captcha with a token from elsewhere or during an outage', () => {
  it('refuses a token solved on another hostname before any account work', async () => {
    const { auth, calls, verified } = await app(
      verifier(provider({ success: true, hostname: 'bot-farm.example', action: 'login' })),
    );

    const result = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      captchaToken: 'solved-elsewhere',
      meta: meta(),
    });

    expect(result).toMatchObject({ ok: false, code: 'captcha_failed', reason: 'captcha_rejected' });
    expect(calls).toEqual([]);
    expect(verified).toEqual([]);
  });

  it('refuses a token solved for another form of the same app', async () => {
    const { auth, calls } = await app(
      verifier(provider({ success: true, hostname: HOST, action: 'register' })),
    );

    const result = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      captchaToken: 'solved-on-the-sign-up-form',
      meta: meta(),
    });

    expect(result).toMatchObject({ ok: false, code: 'captcha_failed' });
    expect(calls).toEqual([]);
  });

  it('counts every kind of outage as a failure, on every door the core checks', async () => {
    const down = [
      provider({}, 500),
      provider({ success: false, 'error-codes': ['internal-error'] }),
      provider({ nonsense: true }),
      vi.fn(async () => {
        throw new TypeError('network down');
      }) as unknown as typeof fetch,
      vi.fn(async (_url: unknown, init?: RequestInit) => {
        // A provider that never answers: only the verifier's timeout ends it.
        await new Promise((_resolve, reject) =>
          init?.signal?.addEventListener('abort', () => reject(new Error('timed out'))),
        );
      }) as unknown as typeof fetch,
    ];

    for (const fetch of down) {
      const captcha = turnstile({
        secret: 'turnstile-test-secret',
        expectedHostnames: [HOST],
        checkAction: true,
        timeoutMs: 20,
        fetch,
      });

      const { auth, calls, verified } = await app(captcha);
      const token = 'a-real-looking-token';

      const answers = [
        await auth.login({ email: EMAIL, password: PASSWORD, captchaToken: token, meta: meta() }),
        await auth.register({
          email: 'grace@example.com',
          password: PASSWORD,
          captchaToken: token,
          meta: meta(),
        }),
        await auth.requestPasswordReset({ email: EMAIL, captchaToken: token, meta: meta() }),
      ];

      expect(answers.map((a) => !a.ok && a.code)).toEqual([
        'captcha_unavailable',
        'captcha_unavailable',
        'captcha_unavailable',
      ]);

      expect(calls).toEqual([]);
      expect(verified).toEqual([]);
    }
  });

  it('refuses a missing or oversized token without asking the provider', async () => {
    const fetch = provider({ success: true, hostname: HOST, action: 'login' });
    const { auth } = await app(verifier(fetch));

    const missing = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    const oversized = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      captchaToken: 'x'.repeat(2049),
      meta: meta(),
    });

    expect([missing, oversized].map((a) => !a.ok && a.code)).toEqual([
      'captcha_failed',
      'captcha_failed',
    ]);

    expect(fetch).not.toHaveBeenCalled();
  });

  it('lets a token solved on this hostname for this form through to the password check', async () => {
    const { auth, verified } = await app(
      verifier(provider({ success: true, hostname: HOST, action: 'login' })),
    );

    const result = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      captchaToken: 'solved-here',
      meta: meta(),
    });

    expect(result.ok).toBe(true);
    expect(verified).toHaveLength(1);
  });
});
