import { createAuth, type Mailer } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores, PrismaTwoFactorStore } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import { twoFactor } from '@noctcore/auth/two-factor';
import { Redis } from 'ioredis';
import { aesGcmCipher } from './cipher';
import { prisma } from '../node-server/db';

const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');

const cipher = aesGcmCipher(
  new Map([['k1', Buffer.from(process.env.TOTP_KEY_K1 ?? '', 'base64')]]),
  'k1',
);

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
      twoFactor({
        store: new PrismaTwoFactorStore({
          factor: prisma.authTwoFactor,
          recoveryCodes: prisma.authRecoveryCodes,
          trustedDevice: prisma.authTrustedDevice,
          stepUp: prisma.authStepUp,
        }),
        cipher,
        issuer: 'Acme',
        // Who must have a factor: admins here. Without one they get an enrollment challenge.
        required: ({ user }) => user.email.endsWith('@acme.example'),
      }),
    ],
  });
}

export type AppAuth = ReturnType<typeof buildAuth>;
