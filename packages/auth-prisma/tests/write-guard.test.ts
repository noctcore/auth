// The app's own write guard (`writeWhere`): it goes into the `where` of every
// credential write through `AND`, so it can only narrow the write, and it
// stays out of reads and of an email revert.
import { describe, expect, it } from 'vitest';
import { AuthConfigError, type NormalizedEmail } from '@noctcore/auth';
import { DbNull, Decimal, JsonNull } from '@prisma/client/runtime/client';
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

/** The refusal for a condition that matches every row, at `path`. */
const ALL_AT = (path: string) => `a condition that matches every row at ${path},`;

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

  it('allows the empty relation filters that narrow: some and none', async () => {
    const { delegate, calls } = recording();

    const writeWhere = {
      memberships: { some: {} },
      bans: { none: {} },
      OR: [{ teams: { some: {}, none: { archived: true } } }],
    };

    const store = new PrismaUserStore({ delegate, writeWhere });

    await store.setPasswordHash('u1', 'hash');

    expect(whereOf(calls)).toEqual([{ AND: [{ id: 'u1', deletedAt: null }, writeWhere] }]);
  });

  it('refuses a condition that matches every row wherever its shape shows it', () => {
    const { delegate } = recording();

    for (const [writeWhere, at] of [
      // "Matches no row" carried through an OR, a relation filter and `in: []`.
      [{ NOT: { OR: [{ OR: [] }] } }, 'writeWhere.NOT'],
      [{ NOT: { OR: [{ OR: [] }, { closedAt: { in: [] } }] } }, 'writeWhere.NOT'],
      [{ NOT: { closedAt: { in: [] } } }, 'writeWhere.NOT'],
      [{ NOT: [{ memberships: { some: { OR: [] } } }] }, 'writeWhere.NOT'],
      [{ NOT: { profile: { is: { id: { in: [] } } } } }, 'writeWhere.NOT'],
      [{ memberships: { none: { OR: [] } } }, 'writeWhere.memberships'],
      [{ profile: { isNot: { OR: [] } } }, 'writeWhere.profile'],
      [{ closedAt: { notIn: [] } }, 'writeWhere.closedAt'],
      [{ closedAt: { not: { in: [] } } }, 'writeWhere.closedAt'],
      // Inside a relation filter too, and a match-all branch makes its OR match all.
      [{ memberships: { every: { NOT: { OR: [] } } } }, 'writeWhere.memberships.every.NOT'],
      [{ OR: [{ closedAt: null }, { orgId: { notIn: [] } }] }, 'writeWhere.OR[1].orgId'],
      // The two halves of one relation and condition, split over an OR.
      [{ OR: [{ memberships: { some: {} } }, { memberships: { none: {} } }] }, 'writeWhere.OR'],
      [
        {
          OR: [{ profile: { is: { verified: true } } }, { profile: { isNot: { verified: true } } }],
        },
        'writeWhere.OR',
      ],
      [
        {
          OR: [
            { memberships: { some: { since: { in: [new Date(0)] } } } },
            { memberships: { none: { since: { in: [new Date(0)] } } } },
          ],
        },
        'writeWhere.OR',
      ],
    ] as const)
      expect(() => new PrismaUserStore({ delegate, writeWhere })).toThrow(ALL_AT(at));

    // `some` and `none` (or `is` and `isNot`) of one condition on one relation: no row, or every row under NOT.
    for (const writeWhere of [
      { memberships: { some: {}, none: {} } },
      { NOT: { memberships: { some: {}, none: {} } } },
      { profile: { is: { verified: true }, isNot: { verified: true } } },
    ])
      expect(() => new PrismaUserStore({ delegate, writeWhere })).toThrow(
        /(some and none|is and isNot) of the same condition on one relation/u,
      );

    // What still narrows is left alone.
    for (const writeWhere of [
      { memberships: { some: { active: true }, none: { banned: true } } },
      { OR: [{ memberships: { some: { active: true } } }, { memberships: { none: {} } }] },
      { OR: [{ closedAt: { in: [] } }, { orgId: 'o1' }] },
      { NOT: { closedAt: { in: ['2026-01-01'] } } },
      // NOT of a list is "none of them": one entry that matches nothing leaves the others.
      { NOT: [{ closedAt: null }, { memberships: { some: { OR: [] } } }] },
      { memberships: { none: { OR: [{ OR: [] }, { banned: true }] } } },
      // A to-one relation filtered through `is`, with a to-many filter inside.
      { profile: { is: { badges: { some: {} } } } },
      { profile: { is: null }, org: { isNot: null }, orgId: { notIn: ['o2'] } },
      { OR: { closedAt: null } },
      // Matches no row: it guards every write shut, which narrows.
      { closedAt: { not: { notIn: [] } } },
      { OR: [{ memberships: { some: {} }, closedAt: null }, { memberships: { none: {} } }] },
    ])
      expect(() => new PrismaUserStore({ delegate, writeWhere })).not.toThrow();
  });

  it('boots a guard that holds bigints, Decimals, Dates, bytes or Prisma nulls', () => {
    const { delegate } = recording();

    // Narrowing guards whose values JSON cannot write: the analysis must read them, not throw.
    for (const writeWhere of [
      { OR: [{ orgId: { equals: 1n } }, { teamId: { equals: 2n } }] },
      { OR: [{ orgId: { in: [1n, 2n] } }, { ownerId: null }] },
      { memberships: { some: { orgId: 1n }, none: { orgId: 2n } } },
      { memberships: { some: { credit: new Decimal('1.5') }, none: { credit: new Decimal('2') } } },
      { memberships: { some: { since: new Date(0) }, none: { since: new Date(1) } } },
      { memberships: { some: { key: new Uint8Array([1]) }, none: { key: new Uint8Array([2]) } } },
      { memberships: { some: { data: DbNull }, none: { data: JsonNull } } },
      { OR: [{ at: { equals: new Date(Number.NaN) } }, { ownerId: null }] },
    ])
      expect(() => new PrismaUserStore({ delegate, writeWhere })).not.toThrow();

    // The same values on both halves are still the same condition.
    for (const value of [1n, new Decimal('1.5'), new Date(0), new Uint8Array([1, 2]), DbNull])
      expect(
        () =>
          new PrismaUserStore({
            delegate,
            writeWhere: { memberships: { some: { v: value }, none: { v: value } } },
          }),
      ).toThrow('some and none of the same condition on one relation');

    // A value it cannot read at all never makes two conditions equal.
    const read = () => 'never';

    expect(
      () =>
        new PrismaUserStore({
          delegate,
          writeWhere: { memberships: { some: { v: read }, none: { v: read } } } as never,
        }),
    ).not.toThrow();
  });

  it('refuses the empty relation filters that do not narrow, and every match-all it can see', () => {
    const { delegate } = recording();
    // Lists with an empty slot: one at the end, one at the start.
    const hole = [{ closedAt: null }];
    const leading: unknown[] = [];

    hole.length = 2;
    leading[1] = { closedAt: null };

    for (const [writeWhere, message] of [
      // Every related row meets an empty condition, and so does a row with none.
      [{ memberships: { every: {} } }, 'an empty object at writeWhere.memberships.every'],
      // A required relation always has its row; `isNot: null` says what is meant.
      [{ org: { is: {} } }, 'an empty object at writeWhere.org.is'],
      // `some` and `none` are relation filters, never conditions of their own.
      [{ some: {} }, 'an empty object at writeWhere.some'],
      [{ AND: [{ none: {} }] }, 'an empty object at writeWhere.AND[0].none'],
      // Without `is`, a to-one relation's fields read as a column's filter (fails closed).
      [{ profile: { badges: { some: {} } } }, 'an empty object at writeWhere.profile.badges.some'],
      [{ NOT: { OR: [] } }, ALL_AT('writeWhere.NOT')],
      [{ NOT: [{ closedAt: null, OR: [] }] }, ALL_AT('writeWhere.NOT')],
      [{ closedAt: null, NOT: { AND: [{ OR: [] }] } }, ALL_AT('writeWhere.NOT')],
      [{ AND: leading }, 'an empty slot in a list at writeWhere.AND[0]'],
      [{ OR: hole }, 'an empty slot in a list at writeWhere.OR[1]'],
    ] as const)
      expect(() => new PrismaUserStore({ delegate, writeWhere })).toThrow(message);

    // `OR: []` outside a NOT, or inside an OR under it, still only narrows.
    for (const writeWhere of [
      { NOT: { closedAt: { not: null } }, OR: [] },
      { NOT: { OR: [{ OR: [] }, { closedAt: { not: null } }] } },
    ])
      expect(() => new PrismaUserStore({ delegate, writeWhere })).not.toThrow();
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
