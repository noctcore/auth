// A032: getting past a rate limit while its counter store is down.
//
// A limiter that treats "the counter store did not answer" as "under the
// limit" turns an outage (or a store the attacker can overload) into
// unlimited guesses.
//
// Stopped by: auth-trpc src/middlewares.ts: `rateLimited` counts with the
//   core's throttle and refuses with `internal` when the store throws, logging
//   only the error's name.
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { afterEach, describe, expect, it, vi } from 'vitest';
import { boot, Browser, failure, type Booted } from '../support';

describe('A032 rate limit with the counter store down', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('refuses every call while the store cannot count, and leaks nothing about it', async () => {
    booted = await boot();

    const logged: unknown[] = [];

    vi.spyOn(booted.auth.context.logger, 'error').mockImplementation((...args) => {
      logged.push(args);
    });

    const browser = new Browser(booted);

    await browser.client.health.query();

    vi.spyOn(booted.stores.counters, 'increment').mockRejectedValue(
      new Error('ECONNREFUSED redis://user:pw@10.0.0.5'),
    );

    for (let i = 0; i < 5; i += 1) {
      const error = await failure(browser.client.limited.query());

      expect(error.message).toBe('internal');
      expect(JSON.stringify(error.shape)).not.toContain('10.0.0.5');
    }

    expect(JSON.stringify(logged)).not.toContain('10.0.0.5');

    expect(logged[0]).toEqual([
      'auth-trpc rate limit could not count the call',
      { limit: 'ping', error: 'Error' },
    ]);
  });
});
