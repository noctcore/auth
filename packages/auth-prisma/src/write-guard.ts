/**
 * Checking and copying an app's `writeWhere` when the store is built.
 *
 * Some guards would match every row and quietly guard nothing, so they are
 * refused at boot. First by their pieces: an empty guard (`{}`); an
 * `undefined` anywhere inside, which Prisma reads as no filter
 * (`{ orgId: process.env.ORG_ID }` with the variable missing); an empty object
 * anywhere inside, which filters nothing (`{ closedAt: {} }`, `{ AND: [{}] }`);
 * an empty `AND` or `NOT` list, which Prisma reads as true; and a list with an
 * empty slot, which reaches Prisma as `undefined`. Two empty objects narrow
 * and are allowed: `some: {}` and `none: {}` under a to-many relation (at
 * least one related row, no related row). `is: {}` stays refused: on a
 * required relation it holds for every row; write `isNot: null` to ask for a
 * related row.
 *
 * Then by what the shape says a condition matches (`whereReach`). `OR: []`
 * and `in: []` match no row; that is carried through `AND`, `OR`, `NOT`,
 * `not`, and the relation filters `some`, `none`, `is` and `isNot` (and
 * `notIn: []` matches every row). Any condition, at any depth, that comes out
 * as matching every row is refused: `{ NOT: { OR: [] } }`,
 * `{ m: { none: { OR: [] } } }`, `{ p: { isNot: { id: { in: [] } } } }`, an
 * `OR` with such a branch, and an `OR` that splits one relation and condition
 * into its two halves (`some` and `none`, or `is` and `isNot`). The two halves
 * on one key (`{ m: { some: X, none: X } }`) are refused too: they match no
 * row, and every row under a `NOT`. An empty `OR` alone only narrows and is
 * allowed. This reading only adds refusals: a value it cannot read (a bigint,
 * a Decimal, bytes, `Prisma.DbNull`) is compared by its type and text, and any
 * failure of its own leaves the guard allowed rather than failing boot.
 * Match-all forms it does not read pass: `notIn: []` beside another operator
 * of the field (`mode`), `hasEvery: []`, and an `OR` split whose entries hold
 * more keys than the one relation.
 *
 * The guard does not know the model, so it cannot tell a relation from a
 * column. A condition every row meets because of the data, a misplaced
 * relation filter (`{ closedAt: { some: {} } }`) or a typo in a column name is
 * not caught here: Prisma refuses the first guarded write instead. A to-one
 * relation filtered by its fields without `is` (`{ profile: { user: { some:
 * {} } } }`) reads as a column, so its empty `some` is refused; write
 * `{ profile: { is: { user: { some: {} } } } }`. A Date, a Map or a class
 * instance at the top is not a `where` at all and is refused too.
 *
 * The guard is copied and deep-frozen, and every write gets a fresh copy of
 * it, so neither the object the app passed nor a Prisma extension that changes
 * the `where` of one call can change what later writes require.
 */
import { AuthConfigError } from '@noctcore/auth';

const LABEL = 'PrismaUserStore writeWhere';

/** Keys whose empty list Prisma reads as "every row". */
const MATCH_ALL_WHEN_EMPTY = new Set(['AND', 'NOT']);

/** The logical keys of a `where`: their values are conditions, not field filters. */
const LOGICAL = new Set(['AND', 'OR', 'NOT']);

/** To-many relation filters whose empty condition narrows: at least one related row, or none. */
const NARROWING_WHEN_EMPTY = new Set(['some', 'none']);

/**
 * What a value is in a Prisma `where`: a condition (the guard itself, an entry
 * under `AND`, `OR` or `NOT`, the condition of a relation filter) or the
 * filter of one field (`{ gte: 1 }`, `{ some: { ... } }`).
 */
type Role = 'where' | 'filter';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;

  const proto: unknown = Object.getPrototypeOf(value);

  return proto === Object.prototype || proto === null;
}

function refuse(path: string, why: string): never {
  throw new AuthConfigError(`${LABEL} has ${why} at ${path}, which would guard nothing`);
}

/** A deep, frozen copy of plain objects and arrays, refusing what would match every row. */
function checkedCopy(value: unknown, path: string, role: Role): unknown {
  if (value === undefined) refuse(path, 'undefined (Prisma reads it as no filter)');

  if (Array.isArray(value)) {
    const items: unknown[] = [];

    // A plain loop: `map` skips an empty slot and leaves it empty, and Prisma
    // then reads the slot as `undefined`.
    for (let i = 0; i < value.length; i += 1) {
      if (!Object.hasOwn(value, i)) refuse(`${path}[${i}]`, 'an empty slot in a list');

      items.push(checkedCopy(value[i], `${path}[${i}]`, role));
    }

    return Object.freeze(items);
  }

  if (value instanceof Date) return new Date(value.getTime());

  if (!isPlainObject(value)) return value;

  const entries = Object.entries(value);

  if (entries.length === 0) refuse(path, 'an empty object');

  for (const [key, inner] of entries)
    if (MATCH_ALL_WHEN_EMPTY.has(key) && Array.isArray(inner) && inner.length === 0)
      refuse(`${path}.${key}`, 'an empty list (Prisma reads it as true)');

  return Object.freeze(
    Object.fromEntries(
      entries.map(([key, inner]) => {
        const at = `${path}.${key}`;

        if (role === 'filter' && NARROWING_WHEN_EMPTY.has(key) && isEmptyObject(inner))
          return [key, Object.freeze({})];

        const innerRole: Role = role === 'where' && !LOGICAL.has(key) ? 'filter' : 'where';

        return [key, checkedCopy(inner, at, innerRole)];
      }),
    ),
  );
}

function isEmptyObject(value: unknown): boolean {
  return isPlainObject(value) && Object.keys(value).length === 0;
}

/**
 * Which rows a condition can match, as far as its shape tells: `nothing`
 * (`OR: []`, `in: []`), `all` (the negation of nothing, `notIn: []`), or
 * `some` (anything the shape cannot settle, which is most conditions).
 */
type Reach = 'all' | 'nothing' | 'some';

/** Relation filters that, given the same condition, split the rows between them. */
const COMPLEMENT: Readonly<Record<string, string>> = { some: 'none', is: 'isNot' };

function negate(reach: Reach): Reach {
  if (reach === 'all') return 'nothing';

  return reach === 'nothing' ? 'all' : 'some';
}

/** Every part must hold (the keys of a condition, an `AND` list). An empty one holds for every row. */
function both(parts: readonly Reach[]): Reach {
  if (parts.includes('nothing')) return 'nothing';

  return parts.every((part) => part === 'all') ? 'all' : 'some';
}

/**
 * One part must hold (an `OR` list). An empty one holds for no row. No part
 * comes in as `all`: each entry is a condition, refused as soon as it is one.
 */
function either(parts: readonly Reach[]): Reach {
  return parts.every((part) => part === 'nothing') ? 'nothing' : 'some';
}

/** Refuses a condition that matches every row; passes the others through. */
function checked(reach: Reach, path: string): Reach {
  if (reach === 'all') refuse(path, 'a condition that matches every row');

  return reach;
}

/**
 * A stable text for a condition, to tell when two relation filters ask the
 * same thing. Never throws: a guard may hold any value Prisma takes (a
 * bigint, a Decimal, bytes, `Prisma.DbNull`), and a value it cannot read
 * gets a text no other value has, so it never makes two conditions equal.
 */
function canonical(value: unknown): string {
  try {
    return canonicalOf(value);
  } catch {
    unreadable += 1;

    return `unreadable#${unreadable}`;
  }
}

let unreadable = 0;

function canonicalOf(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;

  if (typeof value === 'bigint') return `${value}n`;

  if (value === null || ['string', 'number', 'boolean'].includes(typeof value))
    return String(JSON.stringify(value));

  if (value instanceof Date) return `Date(${value.getTime()})`;

  if (ArrayBuffer.isView(value))
    return `${value.constructor.name}(${Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)).join(' ')})`;

  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();

    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }

  // A class instance (a Decimal, `Prisma.DbNull` or `JsonNull`): its class and
  // its text, so two nulls of different kinds, or two amounts, differ.
  if (typeof value === 'object') {
    const { constructor } = value as { constructor?: { name?: string } };
    const text = (value as { toString: () => string }).toString();

    return `${constructor?.name ?? 'Object'}(${text})`;
  }

  // A function, a symbol or undefined: nothing a condition could be equal to.
  throw new TypeError('not a value');
}

/** The conditions of `AND`, `OR` or `NOT`: a list, or one condition written without a list. */
function conditionsOf(value: unknown, path: string): Reach[] {
  if (Array.isArray(value)) return value.map((item, i) => whereReach(item, `${path}[${i}]`));

  return [whereReach(value, path)];
}

/**
 * An `OR` whose entries include `{ m: { some: X } }` and `{ m: { none: X } }`
 * (or `is` and `isNot`) for the same relation and condition holds for every row.
 */
function splitsTheRows(entries: unknown): boolean {
  if (!Array.isArray(entries)) return false;

  // The relation filters each entry of one key and one filter asks, by relation and condition.
  const asked = new Map<string, Set<string>>();

  for (const entry of entries) {
    const [field, filter] = soleEntry(entry) ?? [];
    const [op, condition] = soleEntry(filter) ?? [];

    if (field === undefined || op === undefined) continue;

    const id = JSON.stringify([field, canonical(condition)]);

    asked.set(id, (asked.get(id) ?? new Set<string>()).add(op));
  }

  return [...asked.values()].some((ops) =>
    Object.entries(COMPLEMENT).some(([op, other]) => ops.has(op) && ops.has(other)),
  );
}

/** The one key and value of an object that has exactly one, or undefined. */
function soleEntry(value: unknown): [string, unknown] | undefined {
  if (!isPlainObject(value)) return undefined;

  const entries = Object.entries(value);

  return entries.length === 1 ? entries[0] : undefined;
}

/** Which rows a condition (an object of fields and `AND`, `OR`, `NOT`) can match. */
function whereReach(value: unknown, path: string): Reach {
  if (!isPlainObject(value)) return 'some';

  const parts = Object.entries(value).map(([key, inner]): Reach => {
    const at = `${path}.${key}`;

    if (key === 'AND') return checked(both(conditionsOf(inner, at)), at);

    if (key === 'OR')
      return checked(splitsTheRows(inner) ? 'all' : either(conditionsOf(inner, at)), at);

    // NOT of a list is "none of them": every entry negated, all of them holding.
    if (key === 'NOT') return checked(both(conditionsOf(inner, at).map(negate)), at);

    return checked(filterReach(inner, at), at);
  });

  return checked(both(parts), path);
}

/** Which rows one field's filter can match. */
function filterReach(value: unknown, path: string): Reach {
  if (!isPlainObject(value)) return 'some';

  for (const [op, other] of Object.entries(COMPLEMENT))
    if (op in value && other in value && canonical(value[op]) === canonical(value[other]))
      refuse(
        `${path}.${op}`,
        `${op} and ${other} of the same condition on one relation (together they match no row, and every row under NOT)`,
      );

  const parts = Object.entries(value).map(([op, inner]): Reach => {
    const at = `${path}.${op}`;
    const empty = isPlainObject(inner) && Object.keys(inner).length === 0;

    switch (op) {
      case 'in':
        return Array.isArray(inner) && inner.length === 0 ? 'nothing' : 'some';
      case 'notIn':
        return Array.isArray(inner) && inner.length === 0 ? 'all' : 'some';
      case 'some':
      case 'is':
        return !empty && whereReach(inner, at) === 'nothing' ? 'nothing' : 'some';
      case 'none':
      case 'isNot':
        return !empty && whereReach(inner, at) === 'nothing' ? 'all' : 'some';
      case 'every':
        whereReach(inner, at);

        return 'some';
      case 'not':
        return isPlainObject(inner) ? negate(filterReach(inner, at)) : 'some';
      default:
        return 'some';
    }
  });

  return both(parts);
}

/** A fresh, unfrozen copy of a checked guard, for one write. */
export function freshWhere(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(freshWhere);

  if (value instanceof Date) return new Date(value.getTime());

  if (!isPlainObject(value)) return value;

  return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, freshWhere(inner)]));
}

/** The guard, checked, copied and frozen, or undefined when there is none. */
export function copyWriteWhere(writeWhere: unknown): Readonly<Record<string, unknown>> | undefined {
  if (writeWhere === undefined) return undefined;

  if (!isPlainObject(writeWhere))
    throw new AuthConfigError(`${LABEL} must be a plain object, a Prisma where`);

  const copy = checkedCopy(writeWhere, 'writeWhere', 'where') as Readonly<Record<string, unknown>>;

  // The shape analysis only adds refusals. A value it cannot read is no
  // reason to refuse the guard: anything but its own refusal means "cannot
  // judge", and the guard is kept.
  try {
    whereReach(copy, 'writeWhere');
  } catch (error) {
    if (error instanceof AuthConfigError) throw error;
  }

  return copy;
}
