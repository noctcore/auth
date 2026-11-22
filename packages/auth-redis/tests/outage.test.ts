// A Redis that is not there: the stores reject within the bound the README
// documents, instead of holding the request for ioredis's default of about 73 s
// (20 retries per command). Needs no server: the port is one nothing listens on.
import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
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

describe('the bounded client the README documents', () => {
  const clients: Redis[] = [];

  afterEach(() => {
    for (const client of clients.splice(0)) client.disconnect();
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

  it('rejects a session read within the bound', async () => {
    const store = new RedisSessionStore(await outageClient());
    const started = Date.now();

    await expect(store.get('a'.repeat(64))).rejects.toBeInstanceOf(Error);
    expect(Date.now() - started).toBeLessThan(BOUND_MS);
  });

  it('rejects a counter increment within the bound', async () => {
    const store = new RedisCounterStore(await outageClient());
    const started = Date.now();

    await expect(store.increment('k', 60_000)).rejects.toBeInstanceOf(Error);
    expect(Date.now() - started).toBeLessThan(BOUND_MS);
  });
});
