/**
 * Checking and copying an app's `writeWhere` when the store is built.
 *
 * Some guards would match every row and quietly guard nothing, so they are
 * refused at boot: an empty guard (`{}`); an `undefined` anywhere inside, which
 * Prisma reads as no filter (`{ orgId: process.env.ORG_ID }` with the variable
 * missing); an empty object anywhere inside, which filters nothing
 * (`{ closedAt: {} }`, `{ AND: [{}] }`); an empty `AND` or `NOT` list, which
 * Prisma reads as true; a `NOT` around a condition that holds `OR: []` (which
 * matches no row, so its negation matches every row, also through an `AND`
 * inside the `NOT`); and a list with an empty slot, which reaches Prisma as
 * `undefined`. Two empty objects narrow and are allowed: `some: {}` and `none: {}` under a to-many relation (at
 * least one related row, no related row). `is: {}` stays refused: on a
 * required relation it holds for every row; write `isNot: null` to ask for a
 * related row. An empty `OR` list matches no row, so it only narrows and is
 * allowed. A Date, a Map or a class instance at the top is not a `where` at
 * all and is refused too. Other guards that match every row (a condition every
 * row meets) are not detected.
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
function checkedCopy(value: unknown, path: string, role: Role, underNot = false): unknown {
  if (value === undefined) refuse(path, 'undefined (Prisma reads it as no filter)');

  if (Array.isArray(value)) {
    const items: unknown[] = [];

    // A plain loop: `map` skips an empty slot and leaves it empty, and Prisma
    // then reads the slot as `undefined`.
    for (let i = 0; i < value.length; i += 1) {
      if (!Object.hasOwn(value, i)) refuse(`${path}[${i}]`, 'an empty slot in a list');

      items.push(checkedCopy(value[i], `${path}[${i}]`, role, underNot));
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

  // `OR: []` matches no row, and so does every condition that holds it:
  // under `NOT`, that condition matches every row.
  if (role === 'where' && underNot && Array.isArray(value['OR']) && value['OR'].length === 0)
    refuse(`${path}.OR`, 'an empty list under NOT (Prisma reads NOT of it as true)');

  return Object.freeze(
    Object.fromEntries(
      entries.map(([key, inner]) => {
        const at = `${path}.${key}`;

        if (role === 'filter' && NARROWING_WHEN_EMPTY.has(key) && isEmptyObject(inner))
          return [key, Object.freeze({})];

        const innerRole: Role = role === 'where' && !LOGICAL.has(key) ? 'filter' : 'where';

        // NOT of an AND is true when any entry of the AND matches no row.
        const negated = role === 'where' && (key === 'NOT' || (key === 'AND' && underNot));

        return [key, checkedCopy(inner, at, innerRole, negated)];
      }),
    ),
  );
}

function isEmptyObject(value: unknown): boolean {
  return isPlainObject(value) && Object.keys(value).length === 0;
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

  return checkedCopy(writeWhere, 'writeWhere', 'where') as Readonly<Record<string, unknown>>;
}
