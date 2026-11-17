// Every setting read once, at boot, and checked before the app listens.
import { trustedHopsFromEnv } from '@noctcore/auth-nestjs';

export interface AppConfig {
  readonly databaseUrl: string;
  readonly redisUrl: string;
  /** The app's own origin, e.g. https://app.example: the only one allowed to send unsafe requests. */
  readonly origin: string;
  /** At least 32 bytes: code HMACs and trusted-device tokens. */
  readonly authSecret: string;
  /** At least 32 bytes, and different from `authSecret`: signs CSRF tokens only. */
  readonly csrfSecret: string;
  /** Reverse proxies in front of the app; refused unset in production. */
  readonly trustedHops: number;
  /** False only for plain-HTTP local development and tests. */
  readonly secureCookies: boolean;
  /** Key prefix in Redis, so several apps can share one. */
  readonly redisPrefix: string;
}

export const CONFIG = Symbol('config');

export function readConfig(vars: Readonly<Record<string, string | undefined>>): AppConfig {
  const authSecret = vars['AUTH_SECRET'];
  const csrfSecret = vars['CSRF_SECRET'];

  if (!authSecret || !csrfSecret)
    throw new Error(
      'Set AUTH_SECRET and CSRF_SECRET (two different values, 32 bytes or more each)',
    );

  if (authSecret === csrfSecret) throw new Error('Use separate secrets for auth and CSRF');

  const port = vars['PORT'] ?? '3000';

  return {
    databaseUrl: vars['DATABASE_URL'] ?? 'postgresql://auth:auth@localhost:5440/auth',
    redisUrl: vars['REDIS_URL'] ?? 'redis://localhost:6390',
    origin: vars['APP_ORIGIN'] ?? `http://localhost:${port}`,
    authSecret,
    csrfSecret,
    trustedHops: trustedHopsFromEnv(vars),
    secureCookies: vars['NODE_ENV'] === 'production',
    redisPrefix: vars['REDIS_PREFIX'] ?? 'example-nestjs:',
  };
}
