// A035: reading a submitted secret back out of a validation error.
//
// When an input fails validation, tRPC's default error carries the
// validator's message, and validators may quote what they were given. An
// error that echoes a password ends up in client logs, error trackers and
// screenshots.
//
// A body that is not JSON does the same through the parser's message
// (`Unexpected token 'S', "SECRETTOKE"...`), and a stack, which tRPC adds in
// development (any NODE_ENV but production, edge runtimes included), carries
// absolute paths.
//
// Stopped by: auth-trpc src/errors.ts: `authErrorFormatter` answers an input
//   error with `invalid_input` and the paths and issue codes only, a body
//   that does not parse with the fixed `bad_request`, and never sends a stack.
// Learn: Build, "Use with tRPC" (/auth/build/trpc/)
import { afterEach, describe, expect, it } from 'vitest';
import { authErrorFormatter } from '../../src';
import { boot, Browser, failure, type Booted } from '../support';

describe('A035 secret echoed in a validation error', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('answers with where and what kind, never the value', async () => {
    booted = await boot();

    const browser = new Browser(booted);

    await browser.signIn();

    const secret = 'my-secret-value-1234567890';
    const error = await failure(browser.client.echo.mutate({ note: secret }));

    expect(error.message).toBe('invalid_input');
    expect(error.data?.input).toEqual([{ path: ['note'], code: 'too_big' }]);
    expect(JSON.stringify(error.shape)).not.toContain(secret);
  });

  it.each(['fetch', 'node'] as const)(
    'answers a body that is not JSON with a fixed message and no stack (%s)',
    async (transport) => {
      booted = await boot({ transport });

      const browser = new Browser(booted);

      await browser.signIn();

      const secret = 'SECRETTOKEN-0987654321';

      const response = await browser.fetch(`${booted.url}/echo`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: `${secret}{`,
      });

      const text = await response.text();
      const body = JSON.parse(text) as { error: { message: string; data: object } };

      expect(response.status).toBe(400);
      expect(body.error.message).toBe('bad_request');
      expect(body.error.data).not.toHaveProperty('stack');
      expect(text).not.toContain('SECRET');
    },
  );

  it('reads issues defensively', () => {
    const shape = {
      message: 'x',
      code: -32600,
      data: { code: 'BAD_REQUEST', httpStatus: 400, stack: undefined },
    };

    const cause = { issues: [{ path: [Symbol('k'), 0] }, {}] };
    const error = Object.assign(new Error('x'), { code: 'BAD_REQUEST', cause });
    const formatted = authErrorFormatter({ shape, error: error as never });

    expect(formatted.data.input).toEqual([
      { path: ['Symbol(k)', 0], code: 'invalid' },
      { path: [], code: 'invalid' },
    ]);
  });
});
