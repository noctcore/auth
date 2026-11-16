/**
 * The client's IP, which every per-IP limit and audit row depends on.
 *
 * Behind a reverse proxy the socket address is the proxy's, so the real client
 * is in `X-Forwarded-For`. That header is client-controlled up to the first
 * proxy you run, so trust exactly as many hops as you have proxies, counted
 * from the right. Trusting everything lets any client pick its own IP (and its
 * own rate-limit bucket); trusting nothing behind a proxy puts every client in
 * one bucket, so one attacker blocks logins for everyone.
 */
import { AuthConfigError } from '../shared/errors';

const HOPS = /^\d+$/u;

/**
 * Parses a `TRUST_PROXY` style setting. An all-digit value is a hop count
 * (Express reads the STRING "1" as the address 0.0.0.1, which silently trusts
 * nothing). `true` is refused: it trusts every hop, so the client chooses its
 * IP. Anything else (an address list, `loopback`) passes through unchanged.
 */
export function parseTrustProxy(raw: string | undefined): number | string | false {
  if (raw === undefined) return false;

  const value = raw.trim();

  if (value === '' || value === 'false') return false;

  if (value === 'true') {
    throw new AuthConfigError(
      'trust proxy "true" lets any client choose its own IP; set the number of proxy hops',
    );
  }

  return HOPS.test(value) ? Number(value) : value;
}

/**
 * The client IP given the socket address, the `X-Forwarded-For` header and the
 * number of proxies in front of the server. With 0 hops the header is ignored.
 */
export function clientIp(input: {
  remoteAddress: string | undefined;
  forwardedFor?: string | readonly string[] | null | undefined;
  trustedHops: number;
}): string | undefined {
  if (input.trustedHops <= 0) return input.remoteAddress;

  const raw = input.forwardedFor;
  const header: string = typeof raw === 'string' ? raw : raw ? raw.join(',') : '';

  const chain = header
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '');

  if (input.remoteAddress) chain.push(input.remoteAddress);
  if (chain.length === 0) return undefined;

  return chain[Math.max(0, chain.length - 1 - input.trustedHops)];
}

/** An IP coarsened for display in a session list: IPv4 to /24, IPv6 to /48. */
export function maskIp(ip: string): string {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/u.exec(ip.replace(/^::ffff:/u, ''));

  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0`;

  if (ip.includes(':')) {
    const head = ip.split('::')[0] ?? '';
    const groups = head.split(':').filter((g) => g !== '');

    while (groups.length < 3) groups.push('0');

    return `${groups.slice(0, 3).join(':')}::`;
  }

  return 'unknown';
}
