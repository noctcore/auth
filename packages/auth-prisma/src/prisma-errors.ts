/**
 * The Prisma error codes the stores turn into results instead of exceptions.
 */

export const P2002 = 'P2002';
export const P2025 = 'P2025';

export function prismaCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String(error.code)
    : undefined;
}

/**
 * A `PrismaClientValidationError`: the client refused the arguments before
 * sending any statement (an argument the provider does not support, say).
 * Matched by name, so the store needs no runtime import of `@prisma/client`.
 */
export function isValidationError(error: unknown): boolean {
  return error instanceof Error && error.name === 'PrismaClientValidationError';
}

/**
 * An error the Prisma client threw (a validation error, a known request
 * error), matched by name.
 */
function isPrismaClientError(error: unknown): boolean {
  return error instanceof Error && error.name.startsWith('PrismaClient');
}

/**
 * A Prisma client error from a write that carries a password hash (a
 * credential write, a sign-up's insert), rethrown without Prisma's message.
 * That message prints the whole call, the hash in `data` included, and the
 * core logs the message of a failed rehash. The
 * Prisma code, when there is one, is kept. Anything else (an outage) is
 * returned as it is.
 */
export function withoutPrismaMessage(error: unknown, write: string): unknown {
  if (!isPrismaClientError(error)) return error;

  const code = prismaCode(error);

  return Object.assign(
    new Error(
      `Prisma user store: Prisma refused the ${write} write${code ? ` (${code})` : ''}; check writeWhere, fields and createData against your schema`,
    ),
    { name: 'PrismaUserStoreError' },
    code ? { code } : {},
  );
}
