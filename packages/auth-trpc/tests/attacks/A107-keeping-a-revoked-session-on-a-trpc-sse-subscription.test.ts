// A107: keeping a revoked session alive on an open tRPC SSE subscription.
//
// tRPC builds the context once per HTTP request, and a subscription served
// over SSE (`httpSubscriptionLink`, on by default in `@trpc/server` 11) is one
// request that stays open until the client leaves or `sse.maxDurationMs`
// ends it, which has no default. The middlewares run once, when it opens, so
// a browser that signed out, changed its password or had its session revoked
// by an admin kept receiving every event of a stream it opened before.
//
// Stopped by: auth-trpc src/middlewares.ts and src/subscription.ts: every
//   session check (`authed`, `freshAuth`, `role`, the nestjs-trpc guard)
//   keeps a subscription's events behind the check. Before an event leaves,
//   when the last check is older than `revalidateSubscriptions` (default
//   30s), the session is validated again without a touch and its user
//   loaded; a refusal ends the stream with `session_expired` in place of the
//   event, and the procedure's own iterator is returned.
// Learn: Sessions and expiry (/auth/learn/sessions-and-expiry/); Build: Use with tRPC
import { initTRPC } from '@trpc/server';
import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import { observable } from '@trpc/server/observable';
import { describe, expect, it, vi } from 'vitest';
import {
  authErrorFormatter,
  createAuthContext,
  createAuthMiddlewares,
  type AuthContextOptions,
  type AuthProcedureMeta,
  type AuthState,
} from '../../src';
import { CSRF_SECRET, EMAIL, makeAuth, ORIGIN, PASSWORD } from '../support';

const SECOND = 1000;
const META = { ip: '203.0.113.1' };

/** Events the test pushes into an open subscription, one at a time. */
function channel() {
  const queued: string[] = [];
  let wake: (() => void) | undefined;
  const state = { returned: false };

  return {
    state,
    push(value: string) {
      queued.push(value);
      wake?.();
    },
    async *events(signal: AbortSignal | undefined): AsyncGenerator<string> {
      try {
        while (!signal?.aborted) {
          const next = queued.shift();

          if (next !== undefined) {
            yield next;
            continue;
          }

          await new Promise<void>((resolve) => {
            wake = resolve;
            signal?.addEventListener('abort', () => resolve(), { once: true });
          });
        }
      } finally {
        state.returned = true;
      }
    },
  };
}

type Channel = ReturnType<typeof channel>;

const t = initTRPC
  .context<{ auth: AuthState }>()
  .meta<AuthProcedureMeta>()
  .create({ errorFormatter: authErrorFormatter });

const { protectedProcedure, role } = createAuthMiddlewares(t);

function buildRouter(feed: Channel) {
  return t.router({
    ticks: protectedProcedure.subscription(({ signal }) => feed.events(signal)),
    /** The same feed through `authed` and `role`: two checks on one procedure. */
    adminTicks: protectedProcedure
      .use(role('admin'))
      .subscription(({ signal }) => feed.events(signal)),
    /** An observable subscription, which tRPC still accepts. */
    ticksObservable: protectedProcedure.subscription(({ signal }) =>
      observable<string>((emit) => {
        void (async () => {
          for await (const value of feed.events(signal)) emit.next(value);
        })();
      }),
    ),
  });
}

async function setup(options: Partial<AuthContextOptions> = {}) {
  const env = makeAuth();

  await env.auth.register({ email: EMAIL, password: PASSWORD, meta: META });

  const login = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: META });

  if (!login.ok || login.value.kind !== 'session') throw new Error('could not sign in');

  const { cookie } = login.value.session;
  const feed = channel();
  const router = buildRouter(feed);

  const authContext = createAuthContext({
    auth: env.auth,
    trustedHops: 0,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
    roles: () => ['admin'],
    ...options,
  });

  /** Opens the subscription the way `httpSubscriptionLink` does: a GET that stays open. */
  const open = async (path = 'ticks') => {
    const response = await fetchRequestHandler({
      endpoint: '/trpc',
      req: new Request(`${ORIGIN}/trpc/${path}`, {
        headers: { cookie: `${cookie.name}=${cookie.value}`, origin: ORIGIN },
      }),
      router,
      createContext: (opts) => authContext.fetch(opts, { remoteAddress: META.ip }),
    });

    expect(response.headers.get('content-type')).toContain('text/event-stream');

    const { body } = response;

    if (!body) throw new Error('the stream has no body');

    const reader = body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = '';

    /** The next SSE event that is not tRPC's own bookkeeping. */
    const next = async (): Promise<{ event: string; data: string } | 'closed'> => {
      for (;;) {
        const end = buffer.indexOf('\n\n');

        if (end !== -1) {
          const block = buffer.slice(0, end);

          buffer = buffer.slice(end + 2);

          const event = /^event: (.*)$/mu.exec(block)?.[1] ?? 'message';
          const data = /^data: (.*)$/mu.exec(block)?.[1] ?? '';

          if (event === 'connected') continue;

          return { event, data };
        }

        const chunk = await reader.read();

        if (chunk.done) return 'closed';

        buffer += chunk.value;
      }
    };

    return { next, close: () => reader.cancel() };
  };

  const revoke = () => env.auth.logout({ token: cookie.value, meta: META });

  return { env, feed, open, revoke };
}

describe('A107 an open tRPC SSE subscription', () => {
  it('stops sending events once the session is revoked and the bound has passed', async () => {
    const { env, feed, open, revoke } = await setup();
    const stream = await open();

    feed.push('first');
    expect(await stream.next()).toEqual({ event: 'message', data: '"first"' });

    await revoke();
    env.clock.advance(30 * SECOND);
    feed.push('after the revocation');

    // The event must not reach the signed-out browser.
    const refusal = await stream.next();

    expect(refusal).toMatchObject({ event: 'serialized-error' });

    expect(JSON.parse((refusal as { data: string }).data)).toMatchObject({
      message: 'session_expired',
      data: { code: 'UNAUTHORIZED' },
    });

    expect(await stream.next()).toBe('closed');
    // The procedure's own iterator was returned, so its cleanup ran.
    expect(feed.state.returned).toBe(true);
  });

  it('may send events inside the bound, and with 0 refuses the first event after it', async () => {
    const lax = await setup();
    const laxStream = await lax.open();

    await lax.revoke();
    lax.env.clock.advance(29 * SECOND);
    lax.feed.push('inside the bound');
    expect(await laxStream.next()).toEqual({ event: 'message', data: '"inside the bound"' });
    await laxStream.close();

    const strict = await setup({ revalidateSubscriptions: 0 });
    const strictStream = await strict.open();

    await strict.revoke();
    strict.feed.push('right after');
    expect(await strictStream.next()).toMatchObject({ event: 'serialized-error' });
  });

  it('ends the stream when the user is deleted', async () => {
    const { env, feed, open } = await setup({ revalidateSubscriptions: 0 });
    const stream = await open();

    vi.spyOn(env.stores.users, 'findById').mockResolvedValue(null);
    feed.push('to a deleted user');

    const refusal = await stream.next();

    expect(JSON.parse((refusal as { data: string }).data)).toMatchObject({
      message: 'session_expired',
    });
  });

  it('ends an observable subscription too', async () => {
    const { env, feed, open, revoke } = await setup();
    const stream = await open('ticksObservable');

    feed.push('first');
    expect(await stream.next()).toEqual({ event: 'message', data: '"first"' });

    await revoke();
    env.clock.advance(30 * SECOND);
    feed.push('after the revocation');
    expect(await stream.next()).toMatchObject({ event: 'serialized-error' });
  });

  it('checks once per bound without a touch, never while idle, and once for two checks', async () => {
    const { env, feed, open } = await setup();
    const validate = vi.spyOn(env.auth, 'validateRequest');
    const stream = await open('adminTicks');

    // The context validated once when the stream opened.
    expect(validate).toHaveBeenCalledTimes(1);

    feed.push('a');
    feed.push('b');
    expect(await stream.next()).toMatchObject({ data: '"a"' });
    expect(await stream.next()).toMatchObject({ data: '"b"' });
    // Inside the bound: no store read per event.
    expect(validate).toHaveBeenCalledTimes(1);

    // Idle past the bound: nothing is read until the next event.
    env.clock.advance(45 * SECOND);
    expect(validate).toHaveBeenCalledTimes(1);

    feed.push('c');
    expect(await stream.next()).toMatchObject({ data: '"c"' });
    // One revalidation for `authed` and `role` together, and it is passive.
    expect(validate).toHaveBeenCalledTimes(2);
    expect(validate.mock.calls[1]?.[0]).toMatchObject({ touch: false });

    await stream.close();
  });

  it('ends the stream with internal when the store cannot answer, logging only the name', async () => {
    const { env, feed, open } = await setup({ revalidateSubscriptions: 0 });
    const logged = vi.spyOn(env.auth.context.logger, 'error');
    const stream = await open();

    vi.spyOn(env.auth, 'validateRequest').mockRejectedValue(new TypeError('session key abc'));
    feed.push('while the store is down');

    const refusal = await stream.next();

    expect(JSON.parse((refusal as { data: string }).data)).toMatchObject({ message: 'internal' });

    expect(logged).toHaveBeenCalledWith('auth-trpc could not revalidate a subscription', {
      error: 'TypeError',
    });

    expect(JSON.stringify(logged.mock.calls)).not.toContain('session key');
  });

  it('keeps the session it opened with when revalidateSubscriptions is false', async () => {
    const { env, feed, open, revoke } = await setup({ revalidateSubscriptions: false });
    const stream = await open();

    await revoke();
    env.clock.advance(3600 * SECOND);
    feed.push('opted out');
    expect(await stream.next()).toEqual({ event: 'message', data: '"opted out"' });
    await stream.close();
  });
});
