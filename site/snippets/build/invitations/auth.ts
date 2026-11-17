import { createAuth, type Mailer } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { invitations } from '@noctcore/auth/invitations';
import { PrismaInvitationStore, PrismaMembershipStore, prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import { Redis } from 'ioredis';
import { prisma } from '../node-server/db';

const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');

/** Who belongs to which organisation (see the membership guards guide). */
export const members = new PrismaMembershipStore({
  client: prisma,
  member: prisma.authMember,
  scope: prisma.authMemberScope,
});

/** The roles an invitation may hand out. */
const ROLES = new Set(['member', 'admin']);

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
      invitations({
        store: new PrismaInvitationStore({ client: prisma, invitation: prisma.authInvitation }),
        // Owners and admins of the organisation may invite, list and revoke, and
        // only with a role the app knows. Read from the store on every call.
        authorize: async ({ user, scope, payload }) => {
          const actor = await members.findMember(scope, user.id);

          if (actor?.role !== 'owner' && actor?.role !== 'admin') return false;

          return payload === undefined || ROLES.has(payload['role'] ?? '');
        },
        // What accepting means here: a seat with the invited role.
        onAccept: async ({ user, invitation }) => {
          await members.addMember({
            scope: invitation.scope,
            userId: user.id,
            role: invitation.payload['role'] ?? 'member',
          });
        },
        // The token in the fragment: it never reaches a server log or a Referer header.
        url: (token) => `https://app.example/invite#${token}`,
      }),
    ],
  });
}

export type AppAuth = ReturnType<typeof buildAuth>;
