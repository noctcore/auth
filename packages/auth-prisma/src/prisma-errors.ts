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
