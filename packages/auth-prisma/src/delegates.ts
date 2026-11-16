/**
 * The structural shapes of the Prisma model delegates the stores call. Prisma
 * generates a different delegate type per model, so the stores accept anything
 * with these methods.
 */

export interface PrismaUserDelegate {
  findFirst(args: any): PromiseLike<any>;
  create(args: any): PromiseLike<any>;
  updateMany(args: any): PromiseLike<{ count: number }>;
}

export interface PrismaAuthTokenDelegate {
  upsert(args: any): PromiseLike<any>;
  findUnique(args: any): PromiseLike<any>;
  delete(args: any): PromiseLike<any>;
  update(args: any): PromiseLike<any>;
  deleteMany(args: any): PromiseLike<{ count: number }>;
}
