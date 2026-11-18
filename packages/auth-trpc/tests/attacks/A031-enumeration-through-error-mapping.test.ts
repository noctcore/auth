// A031: telling accounts apart through the tRPC error.
//
// The core answers "no such account", "wrong password" and "locked" with one
// public code, but a framework layer can undo that: by sending the internal
// reason as the message, by putting it in the error's cause, by mapping codes
// to different tRPC codes, or by answering sign-up and reset requests with a
// different shape for a known address.
//
// Stopped by: auth-trpc src/errors.ts: `toTRPCError` builds the error from the
//   public code only, with no cause; the mapping is total and an unknown code
//   becomes `internal`; `authErrorFormatter` sends nothing else.
// Learn: Enumeration (/auth/learn/enumeration/); core attack A004
import { afterEach, describe, expect, it } from 'vitest';
import { AUTH_ERROR_TRPC_CODES, AuthTRPCError, toTRPCError } from '../../src';
import { boot, Browser, EMAIL, failure, type Booted } from '../support';

/** The error shape without the procedure path, which differs by design. */
function comparable(shape: unknown): unknown {
  const { data, ...rest } = shape as { data: Record<string, unknown> };

  return { ...rest, data: { ...data, path: null } };
}

describe('A031 enumeration through error mapping', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('answers an unknown email and a wrong password identically', async () => {
    booted = await boot();

    const known = new Browser(booted, '198.51.100.20');
    const unknown = new Browser(booted, '198.51.100.21');

    await known.client.health.query();
    await unknown.client.health.query();

    const a = await failure(
      known.client.login.mutate({ email: EMAIL, password: 'wrong password!' }),
    );

    const b = await failure(
      unknown.client.login.mutate({ email: 'nobody@example.com', password: 'wrong password!' }),
    );

    expect(comparable(a.shape)).toEqual(comparable(b.shape));
    expect(a.message).toBe('invalid_credentials');
    expect(known.lastStatus).toBe(unknown.lastStatus);
    expect(JSON.stringify(a.shape)).not.toMatch(/unknown_email|wrong_password|reason/u);
  });

  it('answers sign-up and reset requests with one shape for a taken and a new address', async () => {
    booted = await boot();

    const browser = new Browser(booted);

    await browser.client.health.query();

    const password = 'another long password';
    const taken = await browser.client.register.mutate({ email: EMAIL, password });
    const fresh = await browser.client.register.mutate({ email: 'new@example.com', password });

    expect(taken).toEqual(fresh);

    const knownReset = await browser.client.requestReset.mutate({ email: EMAIL });
    const unknownReset = await browser.client.requestReset.mutate({ email: 'nobody@example.com' });

    expect(knownReset).toEqual(unknownReset);
  });

  it('never carries the internal reason, and maps an unknown code to internal', () => {
    const error = toTRPCError({ code: 'invalid_credentials', reason: 'locked' } as never);

    expect(error.message).toBe('invalid_credentials');
    expect(error.cause).toBeUndefined();
    expect(JSON.stringify(error.auth)).not.toContain('locked');

    for (const code of ['account_suspended', 'constructor', '__proto__', 42, undefined]) {
      const unknown = toTRPCError({ code } as never);

      expect(unknown).toBeInstanceOf(AuthTRPCError);
      expect(unknown.code).toBe('INTERNAL_SERVER_ERROR');
      expect(unknown.message).toBe('internal');
    }

    expect(AUTH_ERROR_TRPC_CODES.invalid_credentials).toBe(
      AUTH_ERROR_TRPC_CODES.invalid_second_factor,
    );
  });

  it('sends the opt-in account_locked answer with its retry time and nothing else', () => {
    const error = toTRPCError({ code: 'account_locked', retryAfterSeconds: 300 });

    expect(error.code).toBe('FORBIDDEN');
    expect(error.message).toBe('account_locked');
    expect(error.auth).toEqual({ code: 'account_locked', retryAfterSeconds: 300 });
  });
});
