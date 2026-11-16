import { PrismaPg } from '@prisma/adapter-pg';
import { config } from './config';
import { PrismaClient } from './generated/prisma/client';

export const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: config.databaseUrl }),
});
