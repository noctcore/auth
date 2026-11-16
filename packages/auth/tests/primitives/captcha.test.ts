import { describe, expect, it, vi } from 'vitest';

import { turnstile } from '../../src/ports/captcha';

const reply = (body: unknown, status = 200) =>
  vi.fn(async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

describe('turnstile', () => {
  const ctx = { ip: '203.0.113.9', door: 'login' as const };

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
