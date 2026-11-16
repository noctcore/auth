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
