import { parseTrustProxy } from '@noctcore/auth';

function required(name: string): string {
  const value = process.env[name];

  if (!value) throw new Error(`Set ${name}`);

  return value;
}

// parseTrustProxy refuses "true" (any client could pick its IP). A plain
// node:http server can only count hops, so an address list is refused here too.
const trustProxy = parseTrustProxy(process.env.TRUST_PROXY);

if (typeof trustProxy === 'string') throw new Error('TRUST_PROXY must be a number of hops');

export const config = {
  /** At least 32 random bytes: `openssl rand -hex 32`. */
  authSecret: required('AUTH_SECRET'),
  /** A different 32 bytes or more, for CSRF tokens only. */
  csrfSecret: required('CSRF_SECRET'),
  databaseUrl: required('DATABASE_URL'),
  redisUrl: required('REDIS_URL'),
  /** The app's own origin, for example https://app.example. */
  origin: required('APP_ORIGIN'),
  /** How many reverse proxies sit in front of this server. */
  trustedHops: trustProxy === false ? 0 : trustProxy,
  /** False only for plain-HTTP local development. */
  secureCookies: process.env.NODE_ENV === 'production',
};

if (config.authSecret === config.csrfSecret)
  throw new Error('Use separate secrets for auth and CSRF');
