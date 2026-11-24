// The app's own write guard (`writeWhere`): it goes into the `where` of every
// credential write through `AND`, so it can only narrow the write, and it
// stays out of reads and of an email revert.
import { describe, expect, it } from 'vitest';
import { AuthConfigError, type NormalizedEmail } from '@noctcore/auth';
import { PrismaUserStore } from '../src';

const EMAIL = 'ada@example.com' as NormalizedEmail;
const NEW = 'new@example.com' as NormalizedEmail;
const CLOSED = { closedAt: null } as const;

/** A delegate that records each call's arguments and answers one changed row. */
function recording() {
  const calls: { method: string; args: Record<string, unknown> }[] = [];

  const record =
    (method: string, answer: unknown) =>
    async (args: Record<string, unknown>): Promise<unknown> => {
      calls.push({ method, args });

      return answer;
    };

  const delegate = {
    findFirst: record('findFirst', null),
    updateMany: record('updateMany', { count: 1 }),
  };

  return { delegate: delegate as never, calls };
}

const whereOf = (calls: ReturnType<typeof recording>['calls']) => calls.map((c) => c.args['where']);

describe('PrismaUserStore writeWhere', () => {
  it('puts the guard beside the store’s own conditions in every credential write', async () => {
    const { delegate, calls } = recording();
    const store = new PrismaUserStore({ delegate, writeWhere: CLOSED });

    await store.setPasswordHash('u1', 'hash');
    await store.setPasswordHash('u1', 'hash', { expected: 'old' });
    await store.markEmailVerified('u1', EMAIL);
    await store.changeEmail('u1', { from: EMAIL, to: NEW });

    expect(whereOf(calls)).toEqual([
      { AND: [{ id: 'u1', deletedAt: null }, CLOSED] },
      { AND: [{ id: 'u1', passwordHash: 'old', deletedAt: null }, CLOSED] },
      { AND: [{ id: 'u1', email: EMAIL, deletedAt: null }, CLOSED] },
      { AND: [{ id: 'u1', email: EMAIL, deletedAt: null }, CLOSED] },
    ]);
  });

  it('cannot widen a write, even naming the store’s own columns', async () => {
    const { delegate, calls } = recording();
    const store = new PrismaUserStore({ delegate, writeWhere: { id: 'u2', deletedAt: undefined } });

    await store.setPasswordHash('u1', 'hash');

    expect(whereOf(calls)).toEqual([
      {
        AND: [
          { id: 'u1', deletedAt: null },
          { id: 'u2', deletedAt: undefined },
        ],
      },
    ]);
  });

  it('leaves reads and an email revert alone', async () => {
    const { delegate, calls } = recording();
    const store = new PrismaUserStore({ delegate, writeWhere: CLOSED });

    await store.findById('u1');
    await store.findCredentialById('u1');
    await store.findCredentialByEmail(EMAIL);
    await store.changeEmail('u1', { from: NEW, to: EMAIL, clearPassword: true });

    expect(whereOf(calls)).toEqual([
      { id: 'u1', deletedAt: null },
      { id: 'u1', deletedAt: null },
      { email: EMAIL, deletedAt: null },
      { id: 'u1', email: NEW, deletedAt: null },
    ]);
  });

  it('writes as before without one', async () => {
    const { delegate, calls } = recording();

    await new PrismaUserStore({ delegate }).setPasswordHash('u1', 'hash');

    expect(whereOf(calls)).toEqual([{ id: 'u1', deletedAt: null }]);
  });

  it('refuses a guard that is not a where object', () => {
    const { delegate } = recording();

    for (const writeWhere of ['closedAt', null, [CLOSED], 1])
      expect(() => new PrismaUserStore({ delegate, writeWhere: writeWhere as never })).toThrow(
        AuthConfigError,
      );
  });
});
