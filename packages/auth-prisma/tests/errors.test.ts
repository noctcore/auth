// How the Prisma stores map database errors: a unique violation or a missing
// row becomes a result, anything else is rethrown so an outage is never read
// as "no such token" or "address taken".
import { describe, expect, it } from 'vitest';
import type { NormalizedEmail } from '@noctcore/auth';
import { PrismaTokenStore, PrismaUserStore } from '../src';

const prismaError = (code: string) => Object.assign(new Error(code), { code });
const outage = new Error('connection refused');

const token = {
  purpose: 'reset',
  userId: 'u1',
  hash: 'h'.repeat(64),
  expiresAt: Date.UTC(2026, 0, 1),
  attempts: 0,
  data: {},
};

function delegate(overrides: Record<string, (...args: unknown[]) => Promise<unknown>>) {
  return overrides as never;
}

describe('PrismaTokenStore errors', () => {
  it('retries a put once when a concurrent first put won the insert', async () => {
    let calls = 0;

    const store = new PrismaTokenStore(
      delegate({
        upsert: async () => {
          calls++;

          if (calls === 1) throw prismaError('P2002');

          return {};
        },
      }),
    );

    await store.put(token);
    expect(calls).toBe(2);
  });

  it('rethrows any other error from a put, a consume or an attempt increment', async () => {
    const failing = async () => {
      throw outage;
    };

    const store = new PrismaTokenStore(
      delegate({ upsert: failing, delete: failing, update: failing }),
    );

    await expect(store.put(token)).rejects.toBe(outage);
    await expect(store.consume('reset', token.hash)).rejects.toBe(outage);
    await expect(store.incrementAttempts('reset', 'u1', 5)).rejects.toBe(outage);
  });

  it('reads a missing row on consume and on an exhausted increment as null', async () => {
    const missing = async () => {
      throw prismaError('P2025');
    };

    const store = new PrismaTokenStore(delegate({ delete: missing, update: missing }));

    expect(await store.consume('reset', token.hash)).toBeNull();
    expect(await store.incrementAttempts('reset', 'u1', 5)).toBeNull();
  });

  it('reads token data that is not an object as empty', async () => {
    const row = { ...token, expiresAt: new Date(token.expiresAt), data: ['not', 'a', 'map'] };
    const store = new PrismaTokenStore(delegate({ findUnique: async () => row }));

    expect((await store.find('reset', token.hash))?.data).toEqual({});
  });
});

describe('PrismaUserStore errors', () => {
  const email = 'ada@example.com' as NormalizedEmail;

  it('answers null for a taken address and rethrows anything else', async () => {
    const taken = new PrismaUserStore({
      delegate: delegate({
        create: async () => {
          throw prismaError('P2002');
        },
      }),
    });

    const down = new PrismaUserStore({
      delegate: delegate({
        create: async () => {
          throw outage;
        },
      }),
    });

    expect(await taken.create({ email, passwordHash: 'x' })).toBeNull();
    await expect(down.create({ email, passwordHash: 'x' })).rejects.toBe(outage);
  });
});
