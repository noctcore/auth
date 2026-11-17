/**
 * The client IP behind reverse proxies, set up so it cannot be got wrong
 * quietly.
 *
 * `X-Forwarded-For` is written by the client up to the first proxy you run,
 * so the app trusts exactly as many hops as it has proxies, counted from the
 * right (the core's `clientIp` rule). Trusting every hop lets a client choose
 * its own IP and rate-limit bucket; trusting none behind a proxy puts every
 * client in one bucket. A missing setting in production is therefore refused
 * at boot, never read as "trust everything" or "trust nothing".
 *
 * Guide: Build, "Use with NestJS" (the trust-proxy rule).
 */
import type { INestApplication } from '@nestjs/common';
import { AuthConfigError, parseTrustProxy } from '@noctcore/auth';

/** The environment variables read: pass `process.env`. */
export interface TrustProxyEnv {
  readonly TRUST_PROXY?: string | undefined;
  readonly NODE_ENV?: string | undefined;
}

/**
 * The number of trusted proxy hops from `TRUST_PROXY`. Unset (or empty) is 0
 * outside production and refused in production; `false` is 0 anywhere; `true`
 * and anything that is not a hop count (an address list, `loopback`) are
 * refused, because the core counts hops.
 */
export function trustedHopsFromEnv(env: TrustProxyEnv): number {
  const raw = env.TRUST_PROXY;

  if (raw === undefined || raw.trim() === '') {
    if (env.NODE_ENV === 'production') {
      throw new AuthConfigError(
        'TRUST_PROXY must be set in production: the number of reverse proxies in front of the app, 0 when none',
      );
    }

    return 0;
  }

  const parsed = parseTrustProxy(raw);

  if (parsed === false) return 0;

  if (typeof parsed !== 'number') {
    throw new AuthConfigError('TRUST_PROXY must be a number of proxy hops, such as 1');
  }

  return parsed;
}

/**
 * Reads `TRUST_PROXY` as `trustedHopsFromEnv` does and sets Express's
 * `trust proxy` to the same hop count, so `req.ip` in your own code agrees
 * with the IP the auth flows see. Returns the count, for `AuthModule`'s
 * `trustedHops`. Express only: on Fastify, pass `trustProxy: <hops>` to the
 * `FastifyAdapter` instead.
 */
export function configureTrustProxy(app: INestApplication, env: TrustProxyEnv): number {
  const hops = trustedHopsFromEnv(env);
  const instance: unknown = app.getHttpAdapter().getInstance();
  const set = (instance as { set?: unknown }).set;

  if (typeof set !== 'function') {
    throw new AuthConfigError(
      'configureTrustProxy supports the Express adapter; on Fastify pass trustProxy to the FastifyAdapter',
    );
  }

  (set as (name: string, value: number) => void).call(instance, 'trust proxy', hops);

  return hops;
}
