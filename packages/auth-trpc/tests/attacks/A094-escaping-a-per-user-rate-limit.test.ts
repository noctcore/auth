// A094: escaping a per-user rate limit, or spending another user's budget.
//
// With `keyBy: 'user'` a tRPC rate limit counts a signed-in caller by user
// instead of by client IP. An attacker tries to turn that into a way out:
// sending a made-up or stolen-looking session cookie on every call so each
// one lands in a fresh bucket, naming another user so the calls drain that
// user's budget instead of their own, or reading user ids out of the counter
// store's keys.
//
// Stopped by: auth-trpc src/middlewares.ts: the user part of the key comes
//   only from the session the core accepted (`ctx.auth.session`), never from
//   anything the client sent; a cookie the core refused counts by the client
//   IP like any anonymous call; the user part is a hash of the stored user id
//   under `user:`, which no client IP can start with, so the raw id never
//   reaches the counter store and a user bucket never meets an IP bucket.
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/); core A011
import { afterEach, describe, expect, it, vi } from 'vitest';
import { boot, Browser, failure, PASSWORD, type Booted } from '../support';

const OTHER = 'grace@example.com';

describe('A094 escaping a per-user rate limit', () => {
  let booted: Booted | undefined;

  afterEach(async () => {
    await booted?.close();
  });

  it('counts a made-up session cookie by the client IP, so a fresh cookie is no fresh budget', async () => {
    booted = await boot();

    const browser = new Browser(booted);

    await browser.client.health.query();

    const forged = async (i: number) => {
      browser.cookies.set('session', `forged-session-token-${i}`);

      return browser.client.perUser.query();
    };

    await forged(1);
    await forged(2);

    expect((await failure(forged(3))).message).toBe('rate_limited');
    expect((await failure(forged(4))).message).toBe('rate_limited');
  });

  it("keeps each user's budget their own, and the IP's apart from both", async () => {
    booted = await boot();

    await booted.auth.register({ email: OTHER, password: PASSWORD, meta: { ip: '203.0.113.2' } });

    const ada = new Browser(booted);
    const grace = new Browser(booted);

    await ada.signIn();
    await grace.signIn(OTHER);

    // Grace spends her whole budget, from the same IP as Ada.
    await grace.client.perUser.query();
    await grace.client.perUser.query();

    expect((await failure(grace.client.perUser.query())).message).toBe('rate_limited');

    // Ada's budget is untouched, and so is the shared IP's.
    await expect(ada.client.perUser.query()).resolves.toEqual({ pong: true });
    await expect(new Browser(booted).client.perUser.query()).resolves.toEqual({ pong: true });
  });

  it('keeps the raw user id out of the counter store', async () => {
    booted = await boot();

    const hit = vi.spyOn(booted.auth.context.throttle, 'hit');
    const browser = new Browser(booted);

    await browser.signIn();
    await browser.client.perUser.query();

    const scopes = hit.mock.calls.map(([scope]) => scope).filter((s) => s.startsWith('trpc:'));

    expect(scopes).toHaveLength(1);
    expect(scopes[0]).toMatch(/^trpc:per-user:user:[0-9a-f]{64}$/u);
    expect(scopes[0]).not.toContain(booted.userId);
  });
});
