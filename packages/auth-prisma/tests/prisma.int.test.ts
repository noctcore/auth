import { PrismaPg } from '@prisma/adapter-pg';
import { afterAll, describe, expect, it } from 'vitest';
import type { AuthUser, NormalizedEmail } from '@noctcore/auth';
import { runConformance, tokenStoreConformance, uniqueId, userStoreConformance } from '@noctcore/auth/testing';
import { PrismaTokenStore, PrismaUserStore, prismaStores } from '../src';
import { PrismaClient } from './generated/prisma/client';

const url = process.env.DATABASE_URL;
const required = process.env.AUTH_REQUIRE_SERVICES === '1';
if (!url && required) throw new Error('DATABASE_URL is required when AUTH_REQUIRE_SERVICES=1');

describe.skipIf(!url)('prisma stores on postgres', () => {
  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: url ?? '' }) });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  const api = { describe, it };
  runConformance(
    'prisma user store',
    userStoreConformance(new PrismaUserStore({ delegate: prisma.user }), {
      softDelete: async (id) => {
        await prisma.user.update({ where: { id }, data: { deletedAt: new Date() } });
      },
    }),
    api,
  );
  runConformance('prisma token store', tokenStoreConformance(new PrismaTokenStore(prisma.authToken)), api);

  it('maps extra columns into a richer user type', async () => {
    interface Member extends AuthUser {
      readonly displayName: string;
    }
    const { users } = prismaStores<Member>({
      delegate: prisma.user,
      tokenDelegate: prisma.authToken,
      select: { displayName: true },
      createData: () => ({ displayName: 'New member' }),
      toUser: (row) => ({
        id: String(row.id),
        email: String(row.email),
        emailVerified: Boolean(row.emailVerified),
        displayName: String(row.displayName),
      }),
    });
    const created = await users.create({ email: `${uniqueId('m')}@example.com` as NormalizedEmail, passwordHash: 'h' });
    expect(created?.displayName).toBe('New member');
    const found = await users.findCredentialById(created?.id ?? '');
    expect(found).toMatchObject({ displayName: 'New member', passwordHash: 'h' });
  });

  it('stores only the hash and keeps token data as JSON', async () => {
    const tokens = new PrismaTokenStore(prisma.authToken);
    const userId = uniqueId('u');
    await tokens.put({ purpose: 'email-verification', userId, hash: 'f'.repeat(64), expiresAt: Date.now() + 60_000, attempts: 0, data: { email: 'a@example.com' } });
    const row = await prisma.authToken.findUnique({ where: { userId_purpose: { userId, purpose: 'email-verification' } } });
    expect(row?.hash).toBe('f'.repeat(64));
    expect((await tokens.findByUser('email-verification', userId))?.data).toEqual({ email: 'a@example.com' });
  });
});
