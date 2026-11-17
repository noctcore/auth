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

/**
 * The role ceiling, shared by every door that hands out or takes away a role
 * (membership here, invitations too): owners may do anything, admins manage
 * everyone but owners and never give the owner role, members manage nobody.
 */
export function mayManage(actorRole: string, from: string | undefined, to: string | undefined) {
  return actorRole === 'owner' || (actorRole === 'admin' && from !== 'owner' && to !== 'owner');
}

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
        canManage: ({ actor, from, to }) => mayManage(actor.role, from, to),
        // Roles are read from the store on every call and not copied into
        // sessions, so there is nothing to revoke when one changes. Set
        // `revokeSessionsOnChange: true` if your session attributes carry roles.
      }),
    ],
  });
}

export type AppAuth = ReturnType<typeof buildAuth>;
