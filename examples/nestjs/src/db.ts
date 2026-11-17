import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from './generated/prisma/client';

/** The Postgres schema the example's tables live in. */
export const DB_SCHEMA = 'example_nestjs';

export function createPrisma(connectionString: string): PrismaClient {
  return new PrismaClient({ adapter: new PrismaPg({ connectionString }, { schema: DB_SCHEMA }) });
}
