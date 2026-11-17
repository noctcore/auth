import { PrismaPg } from '@prisma/adapter-pg';
import { afterAll, describe, expect, it } from 'vitest';
import type { AuthUser, NormalizedEmail } from '@noctcore/auth';
import {
  runConformance,
  tokenStoreConformance,
  twoFactorStoreConformance,
  uniqueId,
  userStoreConformance,
} from '@noctcore/auth/testing';
import { PrismaTokenStore, PrismaTwoFactorStore, PrismaUserStore, prismaStores } from '../src';
import { PrismaClient } from './generated/prisma/client';

const url = process.env['DATABASE_URL'];
const required = process.env['AUTH_REQUIRE_SERVICES'] === '1';

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

  runConformance(
    'prisma token store',
    tokenStoreConformance(new PrismaTokenStore(prisma.authToken)),
    api,
  );

  const twoFactor = new PrismaTwoFactorStore({
    factor: prisma.authTwoFactor,
    recoveryCodes: prisma.authRecoveryCodes,
    trustedDevice: prisma.authTrustedDevice,
    stepUp: prisma.authStepUp,
  });

  runConformance('prisma two-factor store', twoFactorStoreConformance(twoFactor), api);

  it("deletes a user's expired trusted devices when it adds one", async () => {
    const userId = uniqueId('user');
    const now = Date.now();

    const expired = {
      userId,
      hash: uniqueId('d'),
      epoch: 0,
      createdAt: now - 2000,
      expiresAt: now - 1000,
    };

    const fresh = {
      userId,
      hash: uniqueId('d'),
      epoch: 0,
      createdAt: now,
      expiresAt: now + 60_000,
    };

    await twoFactor.addTrustedDevice(expired, 5);
    await twoFactor.addTrustedDevice(fresh, 5);

    expect(await prisma.authTrustedDevice.findUnique({ where: { hash: expired.hash } })).toBeNull();
    expect(await twoFactor.findTrustedDevice(userId, fresh.hash)).toEqual(fresh);
  });

  it('reads recovery codes stored as something other than a list as none', async () => {
    const userId = uniqueId('user');

    await prisma.authRecoveryCodes.create({ data: { userId, hashes: { not: 'a list' } } });
    expect(await twoFactor.countRecoveryCodes(userId)).toBe(0);
  });

  it('never starts the recovery code version over, so an old spend cannot match a new set', async () => {
    const userId = uniqueId('user');

    await twoFactor.replaceRecoveryCodes(userId, ['old']);

    const before = await prisma.authRecoveryCodes.findUnique({ where: { userId } });

    // Turned off, then on again with a new set.
    await twoFactor.replaceRecoveryCodes(userId, []);
    expect(await twoFactor.countRecoveryCodes(userId)).toBe(0);
    await twoFactor.replaceRecoveryCodes(userId, ['new']);

    const after = await prisma.authRecoveryCodes.findUnique({ where: { userId } });

    expect(after?.version).toBeGreaterThan(before?.version ?? 0);
    expect(await twoFactor.consumeRecoveryCode(userId, 'old')).toBe(false);
    expect(await twoFactor.consumeRecoveryCode(userId, 'new')).toBe(true);
  });

  it('skips stored recovery codes that are not strings', async () => {
    const userId = uniqueId('user');

    await prisma.authRecoveryCodes.create({ data: { userId, hashes: ['a', 1, 'b'] } });
    expect(await twoFactor.countRecoveryCodes(userId)).toBe(2);
  });

  it('answers a taken address with a skipped insert, not a failed statement', async () => {
    const { users } = prismaStores({ delegate: prisma.user, tokenDelegate: prisma.authToken });
    const email = `${uniqueId('dup')}@example.com` as NormalizedEmail;
    const create = prisma.user.create.bind(prisma.user);
    let creates = 0;

    prisma.user.create = ((args: never) => (creates++, create(args))) as never;

    try {
      expect(await users.create({ email, passwordHash: 'h' })).toMatchObject({ email });
      expect(await users.create({ email, passwordHash: 'h2' })).toBeNull();
      expect(creates).toBe(0);
      expect(await users.findCredentialByEmail(email)).toMatchObject({ passwordHash: 'h' });
    } finally {
      prisma.user.create = create as never;
    }
  });

  it('falls back to create when createData has a nested write, which a bulk insert refuses', async () => {
    const users = new PrismaUserStore({
      delegate: prisma.user,
      createData: () => ({ profile: { create: { bio: 'hello' } } }),
    });

    const email = `${uniqueId('nested')}@example.com` as NormalizedEmail;
    const created = await users.create({ email, passwordHash: 'h' });

    expect(created).toMatchObject({ email });

    expect(await prisma.profile.findUnique({ where: { userId: created?.id ?? '' } })).toMatchObject(
      {
        bio: 'hello',
      },
    );

    expect(await users.create({ email, passwordHash: 'h2' })).toBeNull();
  });

  it('falls back to create and a unique violation on a delegate without createManyAndReturn', async () => {
    const delegate = {
      findFirst: prisma.user.findFirst.bind(prisma.user),
      create: prisma.user.create.bind(prisma.user),
      updateMany: prisma.user.updateMany.bind(prisma.user),
    };

    const users = new PrismaUserStore({ delegate });
    const email = `${uniqueId('fallback')}@example.com` as NormalizedEmail;

    expect(await users.create({ email, passwordHash: 'h' })).toMatchObject({ email });
    expect(await users.create({ email, passwordHash: 'h2' })).toBeNull();
  });

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
        id: String(row['id']),
        email: String(row['email']),
        emailVerified: Boolean(row['emailVerified']),
        displayName: String(row['displayName']),
      }),
    });

    const created = await users.create({
      email: `${uniqueId('m')}@example.com` as NormalizedEmail,
      passwordHash: 'h',
    });

    expect(created?.displayName).toBe('New member');
    const found = await users.findCredentialById(created?.id ?? '');

    expect(found).toMatchObject({ displayName: 'New member', passwordHash: 'h' });
  });

  it('stores only the hash and keeps token data as JSON', async () => {
    const tokens = new PrismaTokenStore(prisma.authToken);
    const userId = uniqueId('u');
    const hash = uniqueId('hash');

    await tokens.put({
      purpose: 'email-verification',
      userId,
      hash,
      expiresAt: Date.now() + 60_000,
      attempts: 0,
      data: { email: 'a@example.com' },
    });

    const row = await prisma.authToken.findUnique({
      where: { userId_purpose: { userId, purpose: 'email-verification' } },
    });

    expect(row?.hash).toBe(hash);

    expect((await tokens.findByUser('email-verification', userId))?.data).toEqual({
      email: 'a@example.com',
    });
  });
});
