import { afterEach, describe, expect, it, vi } from 'vitest';

import { turnstile, type TurnstileOptions, type TurnstileOutcome } from '../../src/http/turnstile';

const reply = (body: unknown, status = 200) =>
  vi.fn(async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

const ctx = { ip: '203.0.113.9', door: 'login' as const };

describe('turnstile', () => {
  it('passes a successful token from an expected hostname and action', async () => {
    const verifier = turnstile({
      secret: 's',
      expectedHostnames: ['app.example.com'],
      checkAction: true,
      fetch: reply({ success: true, hostname: 'app.example.com', action: 'login' }),
    });

    expect(await verifier.verify('token', ctx)).toBe('pass');
  });

  it('rejects a token solved on another hostname or for another action', async () => {
    const other = { success: true, hostname: 'evil.example', action: 'login' };

    expect(
      await turnstile({
        secret: 's',
        expectedHostnames: ['app.example.com'],
        fetch: reply(other),
      }).verify('t', ctx),
    ).toBe('reject');

    const wrongAction = { success: true, hostname: 'app.example.com', action: 'register' };

    expect(
      await turnstile({ secret: 's', checkAction: true, fetch: reply(wrongAction) }).verify(
        't',
        ctx,
      ),
    ).toBe('reject');
  });

  it('rejects a missing or oversized token without calling the provider', async () => {
    const fetch = reply({ success: true });
    const verifier = turnstile({ secret: 's', fetch });

    expect(await verifier.verify(undefined, ctx)).toBe('reject');
    expect(await verifier.verify('x'.repeat(3000), ctx)).toBe('reject');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('reports an outage as unavailable, not as a failed challenge', async () => {
    expect(await turnstile({ secret: 's', fetch: reply({}, 500) }).verify('t', ctx)).toBe(
      'unavailable',
    );

    expect(
      await turnstile({
        secret: 's',
        fetch: reply({ success: false, 'error-codes': ['internal-error'] }),
      }).verify('t', ctx),
    ).toBe('unavailable');

    expect(
      await turnstile({ secret: 's', fetch: reply({ nonsense: true }) }).verify('t', ctx),
    ).toBe('unavailable');

    const throwing = vi.fn(async () => {
      throw new TypeError('down');
    }) as unknown as typeof fetch;

    expect(await turnstile({ secret: 's', fetch: throwing }).verify('t', ctx)).toBe('unavailable');
  });

  it('rejects a genuine failure', async () => {
    expect(
      await turnstile({
        secret: 's',
        fetch: reply({ success: false, 'error-codes': ['timeout-or-duplicate'] }),
      }).verify('t', ctx),
    ).toBe('reject');
  });
});

describe('turnstile request', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('posts the secret and token, and the client IP only when there is one', async () => {
    const fetch = reply({ success: true });

    await turnstile({ secret: 'sec', fetch }).verify('tok', { ip: '', door: 'register' });
    await turnstile({ secret: 'sec', fetch }).verify('tok', { ip: '203.0.113.9', door: 'login' });

    const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls as [
      string,
      RequestInit,
    ][];

    const forms = calls.map(([, init]) => new URLSearchParams(init.body as URLSearchParams));

    expect(calls[0]?.[0]).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    expect(calls[0]?.[1].method).toBe('POST');
    expect(forms[0]?.get('secret')).toBe('sec');
    expect(forms[0]?.get('response')).toBe('tok');
    expect(forms[0]?.has('remoteip')).toBe(false);
    expect(forms[1]?.get('remoteip')).toBe('203.0.113.9');
  });

  it('rejects a failure whose error codes are not a list', async () => {
    expect(
      await turnstile({
        secret: 's',
        fetch: reply({ success: false, 'error-codes': 'internal-error' }),
      }).verify('t', ctx),
    ).toBe('reject');
  });

  it('uses the global fetch when none is given', async () => {
    const fetch = reply({ success: true });

    vi.stubGlobal('fetch', fetch);

    expect(await turnstile({ secret: 's' }).verify('t', ctx)).toBe('pass');
    expect(fetch).toHaveBeenCalledOnce();
  });
});

describe('turnstile outcome', () => {
  const TOKEN = 'tok-0123456789-secret-looking-token';
  const SECRET = 'sec-0123456789-turnstile-secret';

  const fetchThrowing = (error: unknown) =>
    vi.fn(async () => {
      throw error;
    }) as unknown as typeof fetch;

  const raw = (body: string, status = 200) =>
    vi.fn(async () => new Response(body, { status })) as unknown as typeof fetch;

  /** A response whose body read fails with `error`. */
  const bodyFails = (error: unknown) =>
    vi.fn(
      async () =>
        new Response(
          new ReadableStream({
            pull() {
              throw error;
            },
          }),
          { status: 200 },
        ),
    ) as unknown as typeof fetch;

  const timeoutError = () => new DOMException('The operation timed out.', 'TimeoutError');

  async function outcomeOf(siteverify: typeof fetch, options: Partial<TurnstileOptions> = {}) {
    const onResult = vi.fn();
    const verifier = turnstile({ secret: SECRET, fetch: siteverify, onResult, ...options });
    const outcome = await verifier.check(TOKEN, ctx);

    expect(onResult).toHaveBeenCalledExactlyOnceWith(outcome);
    expect(await verifier.verify(TOKEN, ctx)).toBe(outcome.verdict);

    return outcome;
  }

  it.each<[string, () => typeof fetch, Record<string, unknown>]>([
    ['timeout', () => fetchThrowing(timeoutError()), { reason: 'timeout' }],
    [
      'timeout (abort)',
      () => fetchThrowing(new DOMException('aborted', 'AbortError')),
      { reason: 'timeout' },
    ],
    [
      'network error',
      () => fetchThrowing(new TypeError('fetch failed')),
      { reason: 'network-error' },
    ],
    [
      'network error while reading the body',
      () => bodyFails(new TypeError('reset')),
      { reason: 'network-error' },
    ],
    ['timeout while reading the body', () => bodyFails(timeoutError()), { reason: 'timeout' }],
    ['non-OK status', () => reply({}, 503), { reason: 'http-status', status: 503 }],
    [
      'body that is not JSON',
      () => raw('<html>captive portal</html>'),
      { reason: 'unparsable-body' },
    ],
    [
      'JSON without a boolean success',
      () => reply({ success: 'yes' }),
      { reason: 'unparsable-body' },
    ],
    ['JSON that is not an object', () => reply(null), { reason: 'unparsable-body' }],
    [
      "Cloudflare's internal-error",
      () => reply({ success: false, 'error-codes': ['internal-error'] }),
      { reason: 'provider-error', errorCodes: ['internal-error'] },
    ],
  ])('says why it is unavailable: %s', async (_name, fetch, expected) => {
    const outcome = await outcomeOf(fetch());

    expect(outcome).toMatchObject({ verdict: 'unavailable', door: 'login', ...expected });

    expect('status' in outcome).toBe(expected['reason'] === 'http-status');
  });

  it('says why a token was refused, with the error codes', async () => {
    expect(
      await outcomeOf(reply({ success: false, 'error-codes': ['timeout-or-duplicate'] })),
    ).toEqual({
      verdict: 'reject',
      reason: 'provider-refused',
      door: 'login',
      errorCodes: ['timeout-or-duplicate'],
    });

    // A wrong secret is a misconfiguration, still refused, and now visible.
    expect(
      await outcomeOf(reply({ success: false, 'error-codes': ['invalid-input-secret'] })),
    ).toMatchObject({ reason: 'provider-refused', errorCodes: ['invalid-input-secret'] });

    expect(
      await outcomeOf(reply({ success: true, hostname: 'evil.example' }), {
        expectedHostnames: ['app.example.com'],
      }),
    ).toMatchObject({ verdict: 'reject', reason: 'hostname-mismatch' });

    expect(
      await outcomeOf(reply({ success: true, action: 'register' }), { checkAction: true }),
    ).toMatchObject({ verdict: 'reject', reason: 'action-mismatch' });
  });

  it('reports a pass, and refusals made without calling the provider', async () => {
    expect(await outcomeOf(reply({ success: true }))).toEqual({
      verdict: 'pass',
      door: 'login',
      errorCodes: [],
    });

    const onResult = vi.fn();
    const verifier = turnstile({ secret: SECRET, fetch: reply({ success: true }), onResult });

    expect(await verifier.check(undefined, ctx)).toMatchObject({ reason: 'missing-token' });

    expect(await verifier.check('x'.repeat(3000), ctx)).toMatchObject({
      reason: 'token-too-long',
    });

    expect(onResult).toHaveBeenCalledTimes(2);
  });

  it('keeps only bounded string error codes', async () => {
    const codes = ['a'.repeat(200), 7, ...Array.from({ length: 20 }, (_, i) => `c${i}`)];
    const outcome = await outcomeOf(reply({ success: false, 'error-codes': codes }));

    expect(outcome.errorCodes).toHaveLength(10);
    expect(outcome.errorCodes[0]).toBe('a'.repeat(64));
  });

  it('a hook that throws, rejects or writes to the outcome does not change the verdict', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };
    const fetch = reply({ success: false, 'error-codes': ['timeout-or-duplicate'] });

    const throwing = turnstile({
      secret: SECRET,
      fetch,
      logger,
      onResult: () => {
        throw new Error('meter down');
      },
    });

    expect(await throwing.verify(TOKEN, ctx)).toBe('reject');

    const rejecting = turnstile({
      secret: SECRET,
      fetch,
      logger,
      onResult: async () => {
        throw new Error('meter rejected');
      },
    });

    expect(await rejecting.verify(TOKEN, ctx)).toBe('reject');
    await new Promise((resolve) => setTimeout(resolve, 0));

    const writing = turnstile({
      secret: SECRET,
      fetch,
      logger,
      onResult: (outcome) => {
        (outcome as { verdict: string }).verdict = 'pass';
      },
    });

    expect(await writing.verify(TOKEN, ctx)).toBe('reject');

    expect(logger.error).toHaveBeenCalledWith('onResult hook failed', {
      provider: 'turnstile',
      error: 'meter down',
    });

    expect(logger.error).toHaveBeenCalledWith('onResult hook failed', {
      provider: 'turnstile',
      error: 'meter rejected',
    });

    // The frozen outcome makes the write throw (strict mode); that is logged too.
    expect(logger.error).toHaveBeenCalledTimes(3);
  });

  it('a slow hook does not hold the verdict up', async () => {
    const verifier = turnstile({
      secret: SECRET,
      fetch: reply({ success: true }),
      onResult: () => new Promise<void>(() => undefined),
    });

    expect(await verifier.verify(TOKEN, ctx)).toBe('pass');
  });

  it('never puts the token or the secret in an outcome or a log line', async () => {
    const seen: unknown[] = [];

    const logger = {
      warn: (...args: unknown[]) => seen.push(args),
      error: (...args: unknown[]) => seen.push(args),
    };

    const onResult = (outcome: TurnstileOutcome) => {
      seen.push(outcome);
      throw new Error('hook failed');
    };

    const fetches = [
      fetchThrowing(timeoutError()),
      fetchThrowing(new TypeError(`fetch failed`)),
      reply({}, 500),
      raw('not json'),
      reply({ success: false, 'error-codes': ['internal-error'] }),
      reply({ success: false, 'error-codes': ['invalid-input-response'] }),
      reply({ success: true, hostname: 'evil.example', action: 'register' }),
      reply({ success: true, hostname: 'app.example.com', action: 'register' }),
      reply({ success: true, hostname: 'app.example.com', action: 'login' }),
    ];

    for (const fetch of fetches) {
      const verifier = turnstile({
        secret: SECRET,
        fetch,
        logger,
        onResult,
        expectedHostnames: ['app.example.com'],
        checkAction: true,
      });

      await verifier.verify(TOKEN, ctx);
      await verifier.verify(undefined, ctx);
      await verifier.verify(`${TOKEN}${'x'.repeat(3000)}`, ctx);
    }

    const text = JSON.stringify(seen);

    expect(seen.length).toBeGreaterThan(fetches.length * 3);
    expect(text).not.toContain(TOKEN);
    expect(text).not.toContain(SECRET);
  });
});
