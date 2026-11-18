/**
 * The client IP behind reverse proxies, set up so it cannot be got wrong
 * quietly.
 *
 * `X-Forwarded-For` is written by the client up to the first proxy you run,
 * so the app trusts exactly as many hops as it has proxies, counted from the
 * right (the core's `clientIp` rule), or trusts its proxies by address (a
 * CIDR list, Express's presets included). Trusting every hop lets a client choose
 * its own IP and rate-limit bucket; trusting none behind a proxy puts every
 * client in one bucket. A missing setting in production is therefore refused
 * at boot, never read as "trust everything" or "trust nothing".
 *
 * Guide: Build, "Use with NestJS" (the trust-proxy rule).
 */
import type { INestApplication } from '@nestjs/common';
import {
  AuthConfigError,
  parseTrustProxy,
  resolveTrustedProxies,
  type TrustedHops,
} from '@noctcore/auth';
import { MAX_TRUSTED_HOPS } from './options';

/** The environment variables read: pass `process.env`. */
export interface TrustProxyEnv {
  readonly TRUST_PROXY?: string | undefined;
  readonly NODE_ENV?: string | undefined;
}

/**
 * The trusted proxies from `TRUST_PROXY`, for `AuthModule`'s `trustedHops`.
 *
 * - A whole number is a hop count, from 0 to 16.
 * - Anything else is a comma-separated list of proxy addresses, CIDR ranges
 *   and the Express presets `loopback`, `linklocal` and `uniquelocal`
 *   (such as `loopback, 10.0.0.0/8`), returned with the presets expanded to
 *   the ranges Express uses.
 * - Unset (or empty) is 0 outside production and refused in production;
 *   `false` is 0 anywhere; `true`, an unknown name and a malformed range are
 *   refused.
 */
export function trustedHopsFromEnv(env: TrustProxyEnv): TrustedHops {
  const raw = env.TRUST_PROXY;

  if (raw === undefined || raw.trim() === '') {
    if (env.NODE_ENV === 'production') {
      throw new AuthConfigError(
        'TRUST_PROXY must be set in production: the number of reverse proxies in front of the app (0 when none), or their addresses',
      );
    }

    return 0;
  }

  const parsed = parseTrustProxy(raw);

  if (parsed === false) return 0;

  if (typeof parsed === 'string') return resolveTrustedProxies(parsed);

  if (!Number.isSafeInteger(parsed) || parsed > MAX_TRUSTED_HOPS) {
    throw new AuthConfigError(
      `TRUST_PROXY must be a number of proxy hops from 0 to ${MAX_TRUSTED_HOPS}, such as 1, or a list of proxy addresses`,
    );
  }

  return parsed;
}

/**
 * Reads `TRUST_PROXY` as `trustedHopsFromEnv` does and sets Express's
 * `trust proxy` to the same hop count or address list, so `req.ip` in your
 * own code agrees with the IP the auth flows see (a `clientIpHeader` is the
 * module's alone: Express does not read it). Returns the value, for
 * `AuthModule`'s `trustedHops`. Express only: on Fastify, pass
 * `trustProxy: <the same value>` to the `FastifyAdapter` instead.
 */
export function configureTrustProxy(app: INestApplication, env: TrustProxyEnv): TrustedHops {
  const hops = trustedHopsFromEnv(env);
  const instance: unknown = app.getHttpAdapter().getInstance();
  const set = (instance as { set?: unknown }).set;

  if (typeof set !== 'function') {
    throw new AuthConfigError(
      'configureTrustProxy supports the Express adapter; on Fastify pass trustProxy to the FastifyAdapter',
    );
  }

  // Express takes a copy: its trust function is compiled from the list once.
  const value = typeof hops === 'number' ? hops : [...hops];

  (set as (name: string, value: number | string[]) => void).call(instance, 'trust proxy', value);

  return hops;
}
