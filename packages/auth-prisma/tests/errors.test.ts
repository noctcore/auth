// How the Prisma stores map database errors: a unique violation or a missing
// row becomes a result, anything else is rethrown so an outage is never read
// as "no such token" or "address taken".
import { describe, expect, it } from 'vitest';
import type { NormalizedEmail } from '@noctcore/auth';
import {
  PrismaMembershipStore,
  PrismaTokenStore,
  PrismaTwoFactorStore,
  PrismaUserStore,
} from '../src';

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

  it('inserts with skipDuplicates when the delegate has createManyAndReturn, and never calls create', async () => {
    const seen: unknown[] = [];
    const row = { id: 'u1', email, emailVerified: false };
    let rows: unknown[] = [row];

    const store = new PrismaUserStore({
      delegate: delegate({
        create: async () => {
          throw new Error('create must not be called');
        },
        createManyAndReturn: async (args) => (seen.push(args), rows),
      }),
      createData: () => ({ tenant: 't1' }),
    });

    expect(await store.create({ email, passwordHash: 'x' })).toEqual(row);

    expect(seen).toEqual([
      {
        data: [{ tenant: 't1', email, passwordHash: 'x' }],
        skipDuplicates: true,
        select: { id: true, email: true, emailVerified: true },
      },
    ]);

    // A taken address: the insert skips the duplicate and returns no row.
    rows = [];
    expect(await store.create({ email, passwordHash: 'x' })).toBeNull();

    const down = new PrismaUserStore({
      delegate: delegate({
        createManyAndReturn: async () => {
          throw outage;
        },
      }),
    });

    await expect(down.create({ email, passwordHash: 'x' })).rejects.toBe(outage);
  });

  it('falls back to create for good once Prisma refuses the bulk insert as invalid', async () => {
    const refusal = Object.assign(new Error('Unknown argument `skipDuplicates`.'), {
      name: 'PrismaClientValidationError',
    });

    const row = { id: 'u1', email, emailVerified: false };
    let bulk = 0;
    let creates = 0;
    let taken = false;

    const store = new PrismaUserStore({
      delegate: delegate({
        createManyAndReturn: async () => {
          bulk++;

          throw refusal;
        },
        create: async () => {
          creates++;

          if (taken) throw prismaError('P2002');

          return row;
        },
      }),
    });

    expect(await store.create({ email, passwordHash: 'x' })).toEqual(row);
    taken = true;
    expect(await store.create({ email, passwordHash: 'x' })).toBeNull();

    // Refused once, remembered: the second sign-up went straight to create.
    expect(bulk).toBe(1);
    expect(creates).toBe(2);

    // Any other error from the bulk insert is an outage, not a refusal.
    const named = Object.assign(new Error('down'), { name: 'PrismaClientKnownRequestError' });

    const down = new PrismaUserStore({
      delegate: delegate({
        createManyAndReturn: async () => {
          throw named;
        },
        create: async () => {
          throw new Error('create must not be called');
        },
      }),
    });

    await expect(down.create({ email, passwordHash: 'x' })).rejects.toBe(named);
    await expect(down.create({ email, passwordHash: 'x' })).rejects.toBe(named);
  });

  it('answers taken for an email change to a taken address and rethrows anything else', async () => {
    const change = { from: email, to: 'grace@example.com' as NormalizedEmail };

    const taken = new PrismaUserStore({
      delegate: delegate({
        updateMany: async () => {
          throw prismaError('P2002');
        },
      }),
    });

    const down = new PrismaUserStore({
      delegate: delegate({
        updateMany: async () => {
          throw outage;
        },
      }),
    });

    expect(await taken.changeEmail('u1', change)).toBe('taken');
    await expect(down.changeEmail('u1', change)).rejects.toBe(outage);
  });
});

describe('PrismaTwoFactorStore errors', () => {
  const unused = delegate({});

  const store = (
    overrides: Partial<
      Record<'factor' | 'recoveryCodes', Record<string, (...args: unknown[]) => Promise<unknown>>>
    >,
  ) =>
    new PrismaTwoFactorStore({
      factor: delegate(overrides.factor ?? {}),
      recoveryCodes: delegate(overrides.recoveryCodes ?? {}),
      trustedDevice: unused,
      stepUp: unused,
    });

  it('tries the guarded update again when a concurrent insert of a pending factor won', async () => {
    let updates = 0;

    const pending = store({
      factor: {
        updateMany: async () => ({ count: updates++ === 0 ? 0 : 1 }),
        create: async () => {
          throw prismaError('P2002');
        },
        findUnique: async () => ({ confirmed: false }),
      },
    });

    expect(await pending.putPendingFactor({ userId: 'u1', secret: 's', createdAt: 0 })).toBe(true);
    expect(updates).toBe(2);
  });

  it('rethrows any other error on a pending factor or a recovery code write', async () => {
    const failing = store({
      factor: {
        updateMany: async () => ({ count: 0 }),
        create: async () => {
          throw outage;
        },
      },
      recoveryCodes: {
        upsert: async () => {
          throw outage;
        },
      },
    });

    await expect(
      failing.putPendingFactor({ userId: 'u1', secret: 's', createdAt: 0 }),
    ).rejects.toBe(outage);

    await expect(failing.replaceRecoveryCodes('u1', ['a'])).rejects.toBe(outage);
  });

  it('writes the recovery codes again when a concurrent first write won the insert', async () => {
    let calls = 0;

    const codes = store({
      recoveryCodes: {
        upsert: async () => {
          if (calls++ === 0) throw prismaError('P2002');

          return {};
        },
      },
    });

    await codes.replaceRecoveryCodes('u1', ['a']);
    expect(calls).toBe(2);
  });
});

describe('PrismaMembershipStore errors', () => {
  const member = { scope: 's1', userId: 'u1', role: 'admin' };
  const input = { scope: 's1', userId: 'u1', from: 'admin', to: 'member', adminRoles: ['owner'] };

  function store(transaction: () => Promise<unknown>, version: number | null = 3) {
    return new PrismaMembershipStore({
      client: { $transaction: transaction },
      member: delegate({
        create: async () => {
          throw outage;
        },
        findUnique: async () => member,
        count: async () => 1,
        update: async () => ({}),
        delete: async () => ({}),
      }),
      scope: delegate({
        findUnique: async () => (version === null ? null : { version }),
        create: async () => ({}),
        update: async () => ({}),
      }),
    });
  }

  it('rethrows an outage from an add, and from a guarded write', async () => {
    const failing = store(async () => {
      throw outage;
    });

    await expect(failing.addMember(member)).rejects.toBe(outage);
    await expect(failing.changeRole(input)).rejects.toBe(outage);
  });

  it('decides again when a concurrent first write created the scope row', async () => {
    let calls = 0;

    const racing = store(async () => {
      if (calls++ === 0) throw prismaError('P2002');

      return [];
    }, null);

    expect(await racing.removeMember(input)).toBe('done');
    expect(calls).toBe(2);
  });

  it('gives up with an error after losing the race fifty times', async () => {
    let calls = 0;

    const losing = store(async () => {
      calls++;

      throw prismaError('P2025');
    });

    await expect(losing.changeRole(input)).rejects.toThrow('lost the race 50 times');
    expect(calls).toBe(50);
  });
});
