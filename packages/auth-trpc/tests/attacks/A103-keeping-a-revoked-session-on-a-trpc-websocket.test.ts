// A103: keeping a revoked session alive on a tRPC WebSocket, or breaking
// every first visit that opens one.
//
// tRPC's WebSocket adapter (`applyWSSHandler`, `getWSConnectionHandler`)
// builds the context once per connection and passes the socket as `res`. A
// socket cannot set headers, so the cookie handouts of a first visit fail and
// tRPC closes the connection with `internal`. A browser whose cookies happen
// to be current connects, and its session is validated once: after a sign-out,
// a password change or a revocation, every query and subscription on that
// socket still runs as the user until the socket closes.
//
// Stopped by: auth-trpc src/context.ts: `createAuthContext(...).node` refuses
//   a `res` that cannot set headers with an `AuthConfigError` naming the
//   reason, before it reads a cookie or validates a session, so no WebSocket
//   connection gets a context at all. WebSocket is not supported yet.
// Learn: Sessions and expiry (/auth/learn/sessions-and-expiry/); Build: Use with tRPC
import { EventEmitter } from 'node:events';
import { AuthConfigError } from '@noctcore/auth';
import { getWSConnectionHandler } from '@trpc/server/adapters/ws';
import { describe, expect, it, vi } from 'vitest';
import { createAuthContext } from '../../src';
import { buildRouter, CSRF_SECRET, EMAIL, makeAuth, ORIGIN, PASSWORD } from '../support';

/** Just enough of a `ws` socket for tRPC's connection handler. */
class FakeSocket extends EventEmitter {
  readyState = 1;
  closed = false;
  readonly sent: unknown[] = [];

  send(data: string): void {
    this.sent.push(JSON.parse(data));
  }

  close(): void {
    this.closed = true;
    this.readyState = 3;
  }
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
}

async function setup() {
  const env = makeAuth();

  await env.auth.register({ email: EMAIL, password: PASSWORD, meta: { ip: '203.0.113.1' } });

  const authContext = createAuthContext({
    auth: env.auth,
    trustedHops: 0,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN] },
  });

  const errors: unknown[] = [];

  const onConnection = getWSConnectionHandler({
    // Read by applyWSSHandler only, which this test stands in for.
    wss: undefined as never,
    router: buildRouter(env.auth),
    // The socket is no Node response: the cast lets the test pass it, as untyped code would.
    createContext: (opts) => authContext.node(opts as never),
    onError: ({ error }) => errors.push(error.cause),
  });

  /** Opens a socket the way `applyWSSHandler` does, with these cookies. */
  const open = (cookie?: string) => {
    const socket = new FakeSocket();

    onConnection(
      socket as never,
      {
        method: 'GET',
        url: '/trpc',
        headers: { host: 'app.test', origin: ORIGIN, ...(cookie ? { cookie } : {}) },
        socket: { remoteAddress: '127.0.0.1' },
      } as never,
    );

    return socket;
  };

  return { env, authContext, errors, open };
}

describe('A103 a tRPC WebSocket connection', () => {
  it('is refused on a first visit with a config error naming the reason, not a crash', async () => {
    const { errors, open } = await setup();

    const socket = open();

    await settle();

    expect(socket.closed).toBe(true);
    expect(socket.sent).toHaveLength(1);
    expect(socket.sent[0]).toMatchObject({ id: null, error: { message: 'internal' } });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(AuthConfigError);
    expect((errors[0] as Error).message).toMatch(/WebSocket and Fastify are not supported yet/);
  });

  it('is refused for a signed-in browser too, so a revoked session cannot live on in it', async () => {
    const { env, authContext, errors, open } = await setup();

    const login = await env.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: { ip: '203.0.113.1' },
    });

    if (!login.ok || login.value.kind !== 'session') throw new Error('could not sign in');

    const { cookie } = login.value.session;
    const session = `${cookie.name}=${cookie.value}`;

    // A plain HTTP request hands out the CSRF cookie bound to the session, so
    // the browser holds current cookies when it opens the socket.
    const headers = new Map<string, string[]>();

    await authContext.node({
      req: { method: 'GET', headers: { cookie: session } },
      res: {
        getHeader: (name) => headers.get(name),
        setHeader: (name, value) => headers.set(name, value as string[]),
      },
    });

    const csrf = (headers.get('set-cookie') ?? []).map((line) => line.split(';')[0]).join('; ');

    expect(csrf).toContain('csrf');

    const socket = open(`${session}; ${csrf}`);

    await settle();

    // Before the refusal this connection opened and kept answering as the
    // user after the sign-out below.
    socket.emit(
      'message',
      Buffer.from(JSON.stringify({ id: 1, method: 'query', params: { path: 'whoami' } })),
      false,
    );

    await settle();
    await env.auth.logout({ token: cookie.value, meta: { ip: '203.0.113.1' } });

    socket.emit(
      'message',
      Buffer.from(JSON.stringify({ id: 2, method: 'query', params: { path: 'whoami' } })),
      false,
    );

    await settle();

    expect(socket.closed).toBe(true);
    expect(JSON.stringify(socket.sent)).not.toContain('"result"');
    expect(errors[0]).toBeInstanceOf(AuthConfigError);
  });

  it('refuses any res that cannot both read and set headers, before reading the request', async () => {
    const { env, authContext } = await setup();
    const validate = vi.spyOn(env.auth, 'validateRequest');

    // A request whose every read throws: the refusal must come first.
    const req = new Proxy(
      {},
      {
        get: () => {
          throw new Error('the request was read');
        },
      },
    );

    for (const res of [
      undefined,
      {},
      { setHeader: () => undefined },
      // A Fastify reply: getHeader and header(), with setHeader only on reply.raw.
      { getHeader: () => undefined, header: () => undefined, raw: { setHeader: () => undefined } },
    ]) {
      const refusal = authContext.node({ req, res } as never);

      await expect(refusal).rejects.toBeInstanceOf(AuthConfigError);
      await expect(refusal).rejects.toThrow(/cannot set headers/);
    }

    expect(validate).not.toHaveBeenCalled();
  });
});
