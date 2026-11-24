/**
 * Checking and copying an app's `writeWhere` when the store is built.
 *
 * Prisma reads an `undefined` filter value as "no filter", so a guard such as
 * `{ orgId: process.env.ORG_ID }` with the variable missing, or `{}`, would
 * match every row and quietly guard nothing. A Date, a Map or a class instance
 * is not a `where` at all. Each is refused at boot instead. The guard is copied,
 * so code that later changes the object it passed cannot change what the
 * store's writes require.
 */
import { AuthConfigError } from '@noctcore/auth';

const LABEL = 'PrismaUserStore writeWhere';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;

  const proto: unknown = Object.getPrototypeOf(value);

  return proto === Object.prototype || proto === null;
}

/** A deep copy of plain objects and arrays; any `undefined` inside is refused. */
function copy(value: unknown, path: string): unknown {
  if (value === undefined)
    throw new AuthConfigError(
      `${LABEL} has undefined at ${path}, which Prisma reads as no filter at all`,
    );

  if (Array.isArray(value)) return value.map((item, i) => copy(item, `${path}[${i}]`));

  if (value instanceof Date) return new Date(value.getTime());

  if (!isPlainObject(value)) return value;

  return Object.fromEntries(
    Object.entries(value).map(([key, inner]) => [key, copy(inner, `${path}.${key}`)]),
  );
}

/** The guard, checked and copied, or undefined when there is none. */
export function copyWriteWhere(writeWhere: unknown): Readonly<Record<string, unknown>> | undefined {
  if (writeWhere === undefined) return undefined;

  if (!isPlainObject(writeWhere))
    throw new AuthConfigError(`${LABEL} must be a plain object, a Prisma where`);

  if (Object.keys(writeWhere).length === 0)
    throw new AuthConfigError(`${LABEL} is empty, so it would guard nothing`);

  return Object.freeze(copy(writeWhere, 'writeWhere') as Record<string, unknown>);
}
