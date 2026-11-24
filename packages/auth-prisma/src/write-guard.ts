/**
 * Checking and copying an app's `writeWhere` when the store is built.
 *
 * Some guards would match every row and quietly guard nothing, so they are
 * refused at boot: an empty guard (`{}`); an `undefined` anywhere inside, which
 * Prisma reads as no filter (`{ orgId: process.env.ORG_ID }` with the variable
 * missing); an empty object anywhere inside, which filters nothing
 * (`{ closedAt: {} }`, `{ AND: [{}] }`); and an empty `AND` or `NOT` list,
 * which Prisma reads as true. An empty `OR` list matches no row, so it only
 * narrows and is allowed. A Date, a Map or a class instance at the top is not
 * a `where` at all and is refused too. Other guards that match every row (a
 * condition every row meets) are not detected.
 *
 * The guard is copied and deep-frozen, and every write gets a fresh copy of
 * it, so neither the object the app passed nor a Prisma extension that changes
 * the `where` of one call can change what later writes require.
 */
import { AuthConfigError } from '@noctcore/auth';

const LABEL = 'PrismaUserStore writeWhere';

/** Keys whose empty list Prisma reads as "every row". */
const MATCH_ALL_WHEN_EMPTY = new Set(['AND', 'NOT']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;

  const proto: unknown = Object.getPrototypeOf(value);

  return proto === Object.prototype || proto === null;
}

function refuse(path: string, why: string): never {
  throw new AuthConfigError(`${LABEL} has ${why} at ${path}, which would guard nothing`);
}

/** A deep, frozen copy of plain objects and arrays, refusing what would match every row. */
function checkedCopy(value: unknown, path: string): unknown {
  if (value === undefined) refuse(path, 'undefined (Prisma reads it as no filter)');

  if (Array.isArray(value))
    return Object.freeze(value.map((item, i) => checkedCopy(item, `${path}[${i}]`)));

  if (value instanceof Date) return new Date(value.getTime());

  if (!isPlainObject(value)) return value;

  const entries = Object.entries(value);

  if (entries.length === 0) refuse(path, 'an empty object');

  for (const [key, inner] of entries)
    if (MATCH_ALL_WHEN_EMPTY.has(key) && Array.isArray(inner) && inner.length === 0)
      refuse(`${path}.${key}`, 'an empty list (Prisma reads it as true)');

  return Object.freeze(
    Object.fromEntries(entries.map(([key, inner]) => [key, checkedCopy(inner, `${path}.${key}`)])),
  );
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

  return checkedCopy(writeWhere, 'writeWhere') as Readonly<Record<string, unknown>>;
}
