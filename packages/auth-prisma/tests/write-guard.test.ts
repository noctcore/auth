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
    const widening = { id: 'u2', deletedAt: { not: null } };
    const store = new PrismaUserStore({ delegate, writeWhere: widening });

    await store.setPasswordHash('u1', 'hash');

    // Both sides must hold: the row must be u1 AND u2, live AND deleted, so nothing matches.
    expect(whereOf(calls)).toEqual([{ AND: [{ id: 'u1', deletedAt: null }, widening] }]);
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

  it('refuses a guard that is not a plain where object', () => {
    const { delegate } = recording();

    class Guard {
      closedAt = null;
    }

    for (const writeWhere of ['closedAt', null, [CLOSED], 1, new Date(), new Map(), new Guard()])
      expect(() => new PrismaUserStore({ delegate, writeWhere: writeWhere as never })).toThrow(
        AuthConfigError,
      );
  });

  it('refuses a guard that would guard nothing: empty, or undefined anywhere inside', () => {
    const { delegate } = recording();
    const env: Record<string, string | undefined> = {};

    for (const writeWhere of [
      {},
      { orgId: env['ORG_ID'] },
      { closedAt: null, orgId: undefined },
      { org: { is: { id: undefined } } },
      { OR: [{ closedAt: null }, { orgId: undefined }] },
      { AND: [] },
      { NOT: [] },
      { closedAt: {} },
      { AND: [{}] },
      { closedAt: null, org: { is: {} } },
    ])
      expect(() => new PrismaUserStore({ delegate, writeWhere })).toThrow(AuthConfigError);

    // An empty OR matches no row: it only narrows, so it is allowed.
    expect(() => new PrismaUserStore({ delegate, writeWhere: { OR: [] } })).not.toThrow();
  });

  it("hands every write a fresh copy, so changing one call's where changes nothing later", async () => {
    const calls: Record<string, unknown>[] = [];

    const store = new PrismaUserStore({
      delegate: {
        updateMany: async (args: { where: { AND: Record<string, unknown>[] } }) => {
          calls.push(structuredClone(args.where));
          // An extension rewriting the guard of this one call.
          const guard = args.where.AND[1] as Record<string, unknown>;

          guard['closedAt'] = { not: null };
          (guard['joinedAt'] as Record<string, unknown>)['gte'] = new Date(5);
          (guard['OR'] as Record<string, unknown>[]).push({ orgId: 'o2' });

          return { count: 1 };
        },
      } as never,
      writeWhere: { closedAt: null, joinedAt: { gte: new Date(0) }, OR: [{ orgId: 'o1' }] },
    });

    await store.setPasswordHash('u1', 'a');
    await store.setPasswordHash('u1', 'b');

    expect(calls[1]).toEqual(calls[0]);

    expect(calls[1]).toEqual({
      AND: [
        { id: 'u1', deletedAt: null },
        { closedAt: null, joinedAt: { gte: new Date(0) }, OR: [{ orgId: 'o1' }] },
      ],
    });
  });

  it('copies the guard, so changing the object afterwards changes nothing', async () => {
    const { delegate, calls } = recording();
    const since = new Date(0);
    const guard: Record<string, unknown> = { closedAt: null, joinedAt: { gte: since } };
    const store = new PrismaUserStore({ delegate, writeWhere: guard });

    guard['closedAt'] = { not: null };
    (guard['joinedAt'] as Record<string, unknown>)['gte'] = new Date(1);
    since.setTime(2);

    await store.setPasswordHash('u1', 'hash');

    expect(whereOf(calls)).toEqual([
      {
        AND: [
          { id: 'u1', deletedAt: null },
          { closedAt: null, joinedAt: { gte: new Date(0) } },
        ],
      },
    ]);
  });

  it("keeps Prisma's message, which prints the new hash, out of a failed credential write", async () => {
    const hash = 'argon2id$secret-new-hash';

    const refusal = Object.assign(
      new Error(
        `Invalid updateMany() invocation: data: { passwordHash: "${hash}" }, Unknown argument closedAtt`,
      ),
      { name: 'PrismaClientValidationError' },
    );

    const known = Object.assign(new Error(`Value too long for ${hash}`), {
      name: 'PrismaClientKnownRequestError',
      code: 'P2000',
    });

    for (const failure of [refusal, known]) {
      const store = new PrismaUserStore({
        delegate: { updateMany: async () => Promise.reject(failure) } as never,
        writeWhere: { closedAtt: null },
      });

      for (const write of [
        () => store.setPasswordHash('u1', hash),
        () => store.markEmailVerified('u1', EMAIL),
        () => store.changeEmail('u1', { from: EMAIL, to: NEW }),
      ]) {
        const error: unknown = await write().catch((caught: unknown) => caught);

        expect(error).toBeInstanceOf(Error);
        expect(error).toMatchObject({ name: 'PrismaUserStoreError' });
        expect(JSON.stringify(error)).not.toContain(hash);
        expect((error as Error).message).not.toContain(hash);
        expect(String((error as Error).stack)).not.toContain(hash);
        expect((error as Error).cause).toBeUndefined();
      }
    }

    // The code survives for a caller that reads it; an outage is passed on untouched.
    const coded = new PrismaUserStore({
      delegate: { updateMany: async () => Promise.reject(known) } as never,
    });

    await expect(coded.setPasswordHash('u1', hash)).rejects.toMatchObject({ code: 'P2000' });

    const outage = new Error('connection refused');

    const down = new PrismaUserStore({
      delegate: { updateMany: async () => Promise.reject(outage) } as never,
    });

    await expect(down.setPasswordHash('u1', hash)).rejects.toBe(outage);
  });
});
