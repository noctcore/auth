import { PrismaPg } from '@prisma/adapter-pg';
import { afterAll, describe, expect, it } from 'vitest';
import {
  createAuth,
  type AuthUser,
  type Logger,
  type NormalizedEmail,
  type PasswordResetJob,
} from '@noctcore/auth';
import {
  invitationStoreConformance,
  memoryStores,
  plainHasher,
  recordingAudit,
  recordingMailer,
  membershipStoreConformance,
  runConformance,
  tokenStoreConformance,
  twoFactorStoreConformance,
  uniqueId,
  userStoreConformance,
} from '@noctcore/auth/testing';
import {
  PrismaInvitationStore,
  PrismaMembershipStore,
  PrismaTokenStore,
  PrismaTwoFactorStore,
  PrismaUserStore,
  prismaStores,
} from '../src';
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

  const members = new PrismaMembershipStore({
    client: prisma,
    member: prisma.authMember,
    scope: prisma.authMemberScope,
  });

  runConformance('prisma membership store', membershipStoreConformance(members), api);

  runConformance(
    'prisma invitation store',
    invitationStoreConformance(
      new PrismaInvitationStore({ client: prisma, invitation: prisma.authInvitation }),
    ),
    api,
  );

  it('bumps the scope version with every guarded write, and decides again after a lost race', async () => {
    const scope = uniqueId('scope');
    const [a, b] = [uniqueId('user'), uniqueId('user')];

    await members.addMember({ scope, userId: a, role: 'admin' });
    await members.addMember({ scope, userId: b, role: 'admin' });
    expect(await prisma.authMemberScope.findUnique({ where: { scope } })).toBeNull();

    const admins = ['admin'];

    expect(
      await members.changeRole({
        scope,
        userId: a,
        from: 'admin',
        to: 'member',
        adminRoles: admins,
      }),
    ).toBe('done');

    expect((await prisma.authMemberScope.findUnique({ where: { scope } }))?.version).toBe(1);

    // A write that bypassed the store but bumped the version: the next guarded
    // write loses its first attempt and decides again on the fresh rows.
    const realFind = prisma.authMemberScope.findUnique.bind(prisma.authMemberScope);
    let first = true;

    const racing = new PrismaMembershipStore({
      client: prisma,
      member: prisma.authMember,
      scope: {
        ...prisma.authMemberScope,
        findUnique: async (args: { where: { scope: string } }) => {
          const row = await realFind(args);

          if (first) {
            first = false;

            await prisma.$transaction([
              prisma.authMember.update({
                where: { scope_userId: { scope, userId: a } },
                data: { role: 'admin' },
              }),
              prisma.authMemberScope.update({ where: { scope }, data: { version: 2 } }),
            ]);
          }

          return row;
        },
        create: prisma.authMemberScope.create.bind(prisma.authMemberScope),
        update: prisma.authMemberScope.update.bind(prisma.authMemberScope),
      },
    });

    expect(await racing.removeMember({ scope, userId: b, from: 'admin', adminRoles: admins })).toBe(
      'done',
    );

    expect(await members.findMember(scope, a)).toEqual({ scope, userId: a, role: 'admin' });
    expect((await prisma.authMemberScope.findUnique({ where: { scope } }))?.version).toBe(3);
  });

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

  describe('writeWhere: credential writes to an account the app closed', () => {
    const PASSWORD = 'correct horse battery';
    const users = new PrismaUserStore({ delegate: prisma.user, writeWhere: { closedAt: null } });

    /** An app on a guarded store, with a reset queue drained by hand. */
    function app(
      options: {
        closeInHook?: boolean;
        store?: PrismaUserStore;
        hasherVersion?: number;
        logger?: Logger;
      } = {},
    ) {
      const memory = memoryStores();
      const mailer = recordingMailer();
      const audit = recordingAudit();
      const jobs: PasswordResetJob[] = [];

      const auth = createAuth({
        stores: {
          users: options.store ?? users,
          tokens: new PrismaTokenStore(prisma.authToken),
          sessions: memory.sessions,
          counters: memory.counters,
        },
        password: { hasher: plainHasher(options.hasherVersion), breachCheck: false },
        secret: 'test-secret-that-is-at-least-32-bytes-long',
        urls: { resetPassword: (token) => `https://app.example/reset#${token}` },
        mailer,
        audit,
        ...(options.logger ? { logger: options.logger } : {}),
        passwordReset: { enqueue: async (job) => void jobs.push(job) },
        hooks: {
          // The hook passes the account, then the app closes it before the write.
          beforePasswordReset: async ({ user }) => {
            if (options.closeInHook === true)
              await prisma.user.update({ where: { id: user.id }, data: { closedAt: new Date() } });
          },
        },
      });

      async function resetLink(email: string) {
        await auth.requestPasswordReset({ email, meta: { ip: '203.0.113.7' } });

        while (jobs.length) await auth.jobs.processPasswordReset(jobs.shift() as PasswordResetJob);

        return (mailer.last('password-reset')?.url ?? '').split('#')[1] ?? '';
      }

      return { auth, audit, resetLink };
    }

    async function account() {
      const email = `${uniqueId('closed')}@example.com`;

      const registered = await app().auth.register({
        email,
        password: PASSWORD,
        meta: { ip: '203.0.113.7' },
      });

      if (!registered.ok) throw new Error(registered.reason);

      const row = await prisma.user.findUniqueOrThrow({ where: { email } });

      return { email, id: row.id, hash: row.passwordHash };
    }

    const close = (id: string) =>
      prisma.user.update({ where: { id }, data: { closedAt: new Date() } });

    it('refuses the reset of a closed account and leaves the hash and the reads alone', async () => {
      const { email, id, hash } = await account();
      const { auth, resetLink } = app();
      const token = await resetLink(email);

      await close(id);

      const reset = await auth.resetPassword({
        token,
        password: 'another long passphrase',
        meta: { ip: '203.0.113.7' },
      });

      expect(!reset.ok && reset.code).toBe('invalid_token');
      expect((await prisma.user.findUniqueOrThrow({ where: { id } })).passwordHash).toBe(hash);

      // Reads still find the row: the guard is for writes only.
      expect(await users.findCredentialByEmail(email as NormalizedEmail)).toMatchObject({ id });
      expect(await users.findById(id)).toMatchObject({ id });
    });

    it('refuses it when the account is closed after the hook passed it', async () => {
      const { email, id, hash } = await account();
      const { auth, resetLink } = app({ closeInHook: true });
      const token = await resetLink(email);

      const reset = await auth.resetPassword({
        token,
        password: 'another long passphrase',
        meta: { ip: '203.0.113.7' },
      });

      expect(!reset.ok && reset.code).toBe('invalid_token');
      expect((await prisma.user.findUniqueOrThrow({ where: { id } })).passwordHash).toBe(hash);
    });

    it('refuses the verified mark and an email change, and still lets a revert through', async () => {
      const { email, id } = await account();
      const to = `${uniqueId('moved')}@example.com` as NormalizedEmail;

      await close(id);

      expect(await users.markEmailVerified(id, email as NormalizedEmail)).toBe(false);
      expect(await users.changeEmail(id, { from: email as NormalizedEmail, to })).toBe('stale');

      // Moved behind the store's back, then reverted: a revert only takes access away.
      await prisma.user.update({ where: { id }, data: { email: to } });

      expect(
        await users.changeEmail(id, {
          from: to,
          to: email as NormalizedEmail,
          clearPassword: true,
        }),
      ).toBe('changed');
    });

    it('writes to an open account as before', async () => {
      const { id } = await account();

      expect(await users.setPasswordHash(id, 'plain$v1$new')).toBe(true);
    });

    it('leaves the hash of a closed account alone at a rehash, and the login goes through', async () => {
      const { email, id, hash } = await account();

      await close(id);

      // A newer hasher: the login proves the password and asks for a rehash.
      const { auth, audit } = app({ hasherVersion: 2 });
      const login = await auth.login({ email, password: PASSWORD, meta: { ip: '203.0.113.7' } });

      expect(login.ok).toBe(true);
      expect(audit.types()).not.toContain('password.rehashed');
      expect((await prisma.user.findUniqueOrThrow({ where: { id } })).passwordHash).toBe(hash);
    });

    describe('with a column Prisma does not know', () => {
      const typo = new PrismaUserStore({ delegate: prisma.user, writeWhere: { closedAtt: null } });

      it("throws at the write without Prisma's message, which would print the hash", async () => {
        const { id } = await account();
        const secret = `plain$v9$${uniqueId('hash')}`;
        const error: unknown = await typo.setPasswordHash(id, secret).catch((e: unknown) => e);

        expect(error).toMatchObject({ name: 'PrismaUserStoreError' });
        expect((error as Error).message).toContain('password hash');

        expect(`${(error as Error).message} ${String((error as Error).stack)}`).not.toContain(
          secret,
        );

        expect(JSON.stringify(error)).not.toContain(secret);
      });

      it('logs a failed rehash without the new hash, and the login goes through', async () => {
        const { email, id } = await account();
        const lines: string[] = [];

        const logger: Logger = {
          warn: (message, context) => void lines.push(`${message} ${JSON.stringify(context)}`),
          error: (message, context) => void lines.push(`${message} ${JSON.stringify(context)}`),
        };

        const { auth } = app({ store: typo, hasherVersion: 2, logger });
        const login = await auth.login({ email, password: PASSWORD, meta: { ip: '203.0.113.7' } });

        expect(login.ok).toBe(true);
        expect(lines.some((line) => line.startsWith('Password rehash failed'))).toBe(true);
        expect(lines.join('\n')).not.toMatch(/plain\$v2\$/u);

        expect((await prisma.user.findUniqueOrThrow({ where: { id } })).passwordHash).toMatch(
          /^plain\$v1\$/u,
        );
      });
    });
  });
});
