import { afterEach, describe, expect, it, vi } from 'vitest';

import { turnstile } from '../../src/http/turnstile';

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
