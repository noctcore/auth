import { parseTrustProxy, resolveTrustedProxies } from '@noctcore/auth';

function required(name: string): string {
  const value = process.env[name];

  if (!value) throw new Error(`Set ${name}`);

  return value;
}

// parseTrustProxy refuses "true" (any client could pick its IP). A hop count
// stays a number; an address list ("loopback, 10.0.0.0/8") is checked and its
// presets expanded, so a typo fails here instead of trusting nothing.
const trustProxy = parseTrustProxy(process.env.TRUST_PROXY);

export const config = {
  /** At least 32 random bytes: `openssl rand -hex 32`. */
  authSecret: required('AUTH_SECRET'),
  /** A different 32 bytes or more, for CSRF tokens only. */
  csrfSecret: required('CSRF_SECRET'),
  databaseUrl: required('DATABASE_URL'),
  redisUrl: required('REDIS_URL'),
  /** The app's own origin, for example https://app.example. */
  origin: required('APP_ORIGIN'),
  /** How many reverse proxies sit in front of this server, or their addresses. */
  trustedHops:
    trustProxy === false
      ? 0
      : typeof trustProxy === 'string'
        ? resolveTrustedProxies(trustProxy)
        : trustProxy,
  /** False only for plain-HTTP local development. */
  secureCookies: process.env.NODE_ENV === 'production',
};

if (config.authSecret === config.csrfSecret)
  throw new Error('Use separate secrets for auth and CSRF');
