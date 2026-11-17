import { createAuth, type Mailer } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { membership } from '@noctcore/auth/membership';
import { PrismaMembershipStore, prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import { Redis } from 'ioredis';
import { prisma } from '../node-server/db';

const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');

/** Who belongs to which organisation. Write memberships only through this store. */
export const members = new PrismaMembershipStore({
  client: prisma,
  member: prisma.authMember,
  scope: prisma.authMemberScope,
});

export function buildAuth(mailer: Mailer) {
  return createAuth({
    stores: {
      ...prismaStores({ delegate: prisma.user, tokenDelegate: prisma.authToken }),
      ...redisStores(redis, { prefix: 'auth:' }),
    },
    password: { hasher: argon2id() },
    secret: process.env.AUTH_SECRET ?? '',
    urls: { resetPassword: (token) => `https://app.example/reset-password#${token}` },
    mailer,
    plugins: [
      membership({
        store: members,
        // The last owner or admin of an organisation can be neither demoted nor removed.
        adminRoles: ['owner', 'admin'],
        // Only an owner may hand out or take away the owner role; admins manage the rest.
        canManage: ({ actor, from, to }) =>
          actor.role === 'owner' ||
          (actor.role === 'admin' && from !== 'owner' && to !== 'owner'),
      }),
    ],
  });
}

export type AppAuth = ReturnType<typeof buildAuth>;
