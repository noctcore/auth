// A Redis that is gone or silent: the stores reject within the bound the README
// documents, instead of holding the request for ioredis's default of about 73 s
// (20 retries per command). Needs no real Redis: one case uses a port nothing
// listens on, the other a fake server that connects and then never answers.
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { Redis } from 'ioredis';
import { afterEach, describe, expect, it } from 'vitest';
import { RedisCounterStore, RedisSessionStore } from '../src';

const BOUND_MS = 3_000;

// The options the README shows, read back from it so the two cannot drift.
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

const bounded = {
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
  connectTimeout: 2_000,
  commandTimeout: 1_000,
  retryStrategy: (attempt: number) => Math.min(attempt * 200, 2_000),
};

async function closedPort(): Promise<number> {
  const server = createServer();

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;

  await new Promise((resolve) => server.close(resolve));

  return port;
}

function portOf(server: Server): number {
  const address = server.address();

  return typeof address === 'object' && address ? address.port : 0;
}

// Answers the handshake (INFO for the ready check, +OK for the rest) and stays
// silent on everything else, as a network that drops packets would.
async function silentRedis(): Promise<Server> {
  const server = createServer((socket) => {
    socket.on('error', () => undefined);

    socket.on('data', (chunk) => {
      for (const command of chunk.toString().split('*').slice(1)) {
        const name = /\$\d+\r\n(\w+)/.exec(command)?.[1]?.toLowerCase();

        if (name === 'info') socket.write('$0\r\n\r\n');
        else if (name !== 'get') socket.write('+OK\r\n');
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  return server;
}

describe('the bounded client the README documents', () => {
  const clients: Redis[] = [];
  const servers: Server[] = [];

  afterEach(() => {
    for (const client of clients.splice(0)) client.disconnect();

    for (const server of servers.splice(0)) server.close();
  });

  async function outageClient(): Promise<Redis> {
    const client = new Redis(`redis://127.0.0.1:${await closedPort()}`, bounded);

    client.on('error', () => undefined);
    clients.push(client);

    return client;
  }

  it('shows every option it tests', () => {
    for (const option of Object.keys(bounded)) expect(readme).toContain(`${option}:`);
  });

  it('rejects a session read on a cold client at once, not after a queue', async () => {
    const store = new RedisSessionStore(await outageClient());
    const started = Date.now();

    await expect(store.get('a'.repeat(64))).rejects.toBeInstanceOf(Error);
    expect(Date.now() - started).toBeLessThan(BOUND_MS);
  });

  it('rejects a counter increment on a cold client at once, not after a queue', async () => {
    const store = new RedisCounterStore(await outageClient());
    const started = Date.now();

    await expect(store.increment('k', 60_000)).rejects.toBeInstanceOf(Error);
    expect(Date.now() - started).toBeLessThan(BOUND_MS);
  });

  it('rejects a command that gets no reply once commandTimeout passes', async () => {
    const server = await silentRedis();

    servers.push(server);

    const client = new Redis(`redis://127.0.0.1:${portOf(server)}`, bounded);

    client.on('error', () => undefined);
    clients.push(client);

    await new Promise((resolve) => client.once('ready', resolve));

    const started = Date.now();

    await expect(new RedisSessionStore(client).get('a'.repeat(64))).rejects.toThrow(
      'Command timed out',
    );

    expect(Date.now() - started).toBeLessThan(BOUND_MS);
  });
});
