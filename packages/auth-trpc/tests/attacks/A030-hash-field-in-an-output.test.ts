// A030: leaking a password or token hash through a procedure's output.
//
// A resolver returns the user record it loaded. The day the record gains a
// field (a password hash, a token hash, an internal flag), every procedure
// that returns it sends that field to the client, and tRPC serialises
// whatever it is given.
//
// Stopped by: auth-trpc src/schemas.ts: the output schemas are plain Zod
//   objects that strip every key they do not name, so a declared `output:`
//   carries only id, email and emailVerified.
// Learn: Build, "Use with tRPC" (/auth/build/trpc/)
import { afterEach, describe, expect, it } from 'vitest';
import { sessionSummaryOutput, userOutput } from '../../src';
import { boot, Browser, type Booted } from '../support';

describe('A030 hash field in an output', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('strips a password hash a resolver returned by mistake', async () => {
    booted = await boot();

    const browser = new Browser(booted);

    await browser.signIn();

    const user = await browser.client.leaky.query();

    expect(user).toEqual({ id: booted.userId, email: 'ada@example.com', emailVerified: false });
    expect(JSON.stringify(user)).not.toContain('hunter2');
  });

  it('keeps only the named keys in every output schema', () => {
    const user = userOutput.parse({
      id: 'u',
      email: 'e',
      emailVerified: true,
      passwordHash: 'h',
      role: 'x',
    });

    expect(Object.keys(user)).toEqual(['id', 'email', 'emailVerified']);

    // A session's store key (`id`) is not a field: only the public handle goes out.
    const summary = sessionSummaryOutput.parse({
      handle: 'h',
      id: 's',
      current: true,
      createdAt: 1,
      lastActiveAt: 1,
      expiresAt: 2,
      ip: '192.0.2.1',
      userAgent: 'ua',
      userId: 'u',
      epoch: 3,
    });

    expect(summary).not.toHaveProperty('id');
    expect(summary).not.toHaveProperty('userId');
    expect(summary).not.toHaveProperty('epoch');
  });
});
