import { createAuth, type AuthUser, type Mailer, type ValidatedSession } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores, PrismaTwoFactorStore } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import { twoFactor, type TwoFactorPolicy } from '@noctcore/auth/two-factor';
import { Redis } from 'ioredis';
import { aesGcmCipher } from './cipher';
import { prisma } from '../node-server/db';

const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');

const cipher = aesGcmCipher(
  new Map([['k1', Buffer.from(process.env.TOTP_KEY_K1 ?? '', 'base64')]]),
  'k1',
);

/** Your tenant's rule: since when it requires a factor, and how long existing members get. */
export interface TenantRule {
  readonly requiredSince: Date | null;
  readonly graceDays: number;
}

const DAY = 24 * 60 * 60 * 1000;

/** The policy is asked on every request of a member without a factor: cache the rule briefly. */
function tenantPolicy(loadRule: (user: AuthUser) => Promise<TenantRule>) {
  const cache = new Map<string, { rule: TenantRule; until: number }>();

  return async ({ user }: { readonly user: AuthUser }): Promise<TwoFactorPolicy> => {
    const hit = cache.get(user.id);
    const rule = hit && hit.until > Date.now() ? hit.rule : await loadRule(user);

    cache.set(user.id, { rule, until: Date.now() + 30_000 });

    if (!rule.requiredSince) return { required: false };

    return { required: true, graceEndsAt: rule.requiredSince.getTime() + rule.graceDays * DAY };
  };
}

export function buildAuth(mailer: Mailer, loadRule: (user: AuthUser) => Promise<TenantRule>) {
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
        // In place of `required`: checked on every request, with a grace window.
        enforcement: tenantPolicy(loadRule),
      }),
    ],
  });
}

export type AppAuth = ReturnType<typeof buildAuth>;

/** Without an adapter: what each route does with the standing validation attached. */
export function gate(session: ValidatedSession<Record<string, never>>, enrollmentRoute: boolean) {
  const standing = session.twoFactor;

  if (standing?.state === 'enrollment-only' && !enrollmentRoute)
    return { status: 403, body: { error: 'two_factor_enrollment_required' } };

  // In the grace window: let it through, and show a banner until graceEndsAt.
  return { status: 200, banner: standing?.state === 'grace' ? standing.graceEndsAt : null };
}

/** From your scheduler, once a day: sign out the members who let the grace window pass. */
export async function sweepTenant(auth: AppAuth, memberIds: AsyncIterable<string>) {
  const { checked, revoked, failed } = await auth.twoFactor.sweepUnenrolled({ userIds: memberIds });

  return { checked, revoked: revoked.length, failed };
}
