import {
  createAuth,
  pwnedPasswords,
  type AuthConfig,
  type AuthUser,
  type Mailer,
} from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';

interface Deps {
  stores: AuthConfig<AuthUser, unknown, []>['stores'];
  mailer: Mailer;
  /** At least 32 bytes, from your secret manager. */
  secret: string;
  origin: string;
}

// The four required keys, the reset link most apps need, and every other
// group written out with its default. Leave a group out and you get the
// same values.
export function authConfig({ stores, mailer, secret, origin }: Deps) {
  return {
    stores,
    secret,
    mailer,
    password: {
      hasher: argon2id(),
      breachCheck: pwnedPasswords(),
      policy: { minLength: 12, maxLength: 256 },
    },
    urls: {
      resetPassword: (token) => `${origin}/reset-password#${token}`,
    },
    session: {
      absoluteTtl: '24h',
      rememberMeTtl: '30d',
      idleTimeout: ({ rememberMe }) => (rememberMe ? '7d' : '30m'),
      touchInterval: '60s',
      maxPerUser: 10,
      freshAuthAge: '10m',
      cookie: { name: 'session', secure: true, sameSite: 'lax' },
    },
    email: { normalize: 'standard' },
    registration: { revealExisting: false, autoLogin: false },
    emailVerification: { kind: 'code', ttl: '15m', digits: 8, maxAttempts: 5 },
    passwordReset: { kind: 'link', ttl: '1h', ticketTtl: '10m', markEmailVerified: true },
    emailChange: { kind: 'code', ttl: '15m', revertTtl: '7d', blockAfterRevert: '30d' },
    throttle: {
      lockout: {
        perAccountIp: { limit: 5, window: '15m' },
        perAccount: { limit: 10, window: '15m' },
        baseLock: '5m',
        maxLock: '1h',
        quietPeriod: '24h',
        revealLocked: false,
      },
      // One entry per door; every door is in the Door limits table.
      doors: { login: { limit: 10, window: '1m' } },
    },
  } satisfies AuthConfig<AuthUser, unknown, []>;
}

export const buildAuth = (deps: Deps) => createAuth(authConfig(deps));
