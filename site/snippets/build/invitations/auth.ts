import { createAuth, type Mailer } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { invitations } from '@noctcore/auth/invitations';
import { PrismaInvitationStore, prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import { Redis } from 'ioredis';
import { prisma } from '../node-server/db';
import { mayManage, members } from '../membership/auth';

const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');

/** The roles an invitation may hand out; `mayManage` decides who may give which. */
const ROLES = new Set(['member', 'admin', 'owner']);

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
        // The membership guide's role ceiling, read from the store on every
        // call: owners and admins may invite, list and revoke, only with a role
        // the app knows, and only an owner may invite an owner.
        authorize: async ({ user, scope, payload }) => {
          const actor = await members.findMember(scope, user.id);
          const role = payload?.['role'];

          if (!actor || (payload !== undefined && !ROLES.has(role ?? ''))) return false;

          return mayManage(actor.role, undefined, role);
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
