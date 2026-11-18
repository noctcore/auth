/**
 * The client's IP, which every per-IP limit and audit row depends on.
 *
 * Behind a reverse proxy the socket address is the proxy's, so the real client
 * is in `X-Forwarded-For`. That header is client-controlled up to the first
 * proxy you run, so trust exactly as many hops as you have proxies, counted
 * from the right. Trusting everything lets any client pick its own IP (and its
 * own rate-limit bucket); trusting nothing behind a proxy puts every client in
 * one bucket, so one attacker blocks logins for everyone. Where the proxies
 * have known addresses, trusting them by address (a CIDR list) is stronger
 * still: a client that reaches the server directly is never mistaken for one.
 */
import { AuthConfigError } from '../shared/errors';
import { isIp, isTrustedAddress, resolveTrustedProxies } from './ip-ranges';

const HOPS = /^\d+$/u;

/**
 * Parses a `TRUST_PROXY` style setting. An all-digit value is a hop count
 * (Express reads the STRING "1" as the address 0.0.0.1, which silently trusts
 * nothing). `true` is refused: it trusts every hop, so the client chooses its
 * IP. Anything else (an address list, `loopback`) passes through unchanged;
 * `resolveTrustedProxies` checks and expands it.
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
 * Which proxies to trust: a hop count (the proxies in front of the server,
 * counted from the right of `X-Forwarded-For`), or a list of proxy addresses,
 * CIDR ranges and the Express presets `loopback`, `linklocal` and
 * `uniquelocal`. With a list, every address in the chain that falls inside it
 * is skipped, from the socket address leftwards, and the first one outside it
 * is the client.
 */
export type TrustedHops = number | readonly string[];

/**
 * Checks a `trustedHops` setting at boot: a whole number from 0 to `maxHops`,
 * or a proxy list (see `resolveTrustedProxies`), returned with its presets
 * expanded. `label` names the setting in the error.
 */
export function resolveTrustedHops(
  value: TrustedHops,
  maxHops: number,
  label = 'trustedHops',
): TrustedHops {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || value > maxHops) {
      throw new AuthConfigError(
        `${label} must be a whole number of proxies from 0 to ${maxHops}, or a list of proxy addresses`,
      );
    }

    return value;
  }

  if (!Array.isArray(value)) {
    throw new AuthConfigError(
      `${label} must be a number of proxies or a list of proxy addresses and ranges`,
    );
  }

  return resolveTrustedProxies(value);
}

const HEADER_NAME = /^[a-z0-9-]+$/u;

/**
 * Checks a `clientIpHeader` setting at boot and returns it lowercased. Refuses
 * `x-forwarded-for` (a list the hop rule already reads, never one address)
 * and anything that is not a header name.
 */
export function resolveClientIpHeader(name: string | undefined): string | undefined {
  if (name === undefined) return undefined;

  const lower = name.trim().toLowerCase();

  if (!HEADER_NAME.test(lower)) throw new AuthConfigError(`Invalid client IP header name: ${name}`);

  if (lower === 'x-forwarded-for') {
    throw new AuthConfigError(
      'clientIpHeader names a single-address header set by your edge, such as cf-connecting-ip; X-Forwarded-For is read through trustedHops',
    );
  }

  return lower;
}

function headerList(raw: string | readonly string[] | null | undefined): string[] {
  const header: string = typeof raw === 'string' ? raw : raw ? raw.join(',') : '';

  return header
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '');
}

/** The one address in a trusted header, or undefined when it is missing or not exactly one IP. */
function singleAddress(raw: string | readonly string[] | null | undefined): string | undefined {
  const values = typeof raw === 'string' ? [raw] : (raw ?? []);

  if (values.length !== 1) return undefined;

  const value = (values[0] ?? '').trim();

  return isIp(value) ? value : undefined;
}

/**
 * The client IP given the socket address, the `X-Forwarded-For` header and
 * the trusted proxies. With 0 hops (or an empty list) the header is ignored.
 *
 * `trustedHeader` is the value of a single-address header your edge sets,
 * such as `cf-connecting-ip`. It wins only when the request came through a
 * trusted proxy (a hop count above 0, or a socket address inside the trusted
 * list) and holds exactly one valid IP; otherwise it is ignored and the
 * `X-Forwarded-For` rule decides, so a client that reaches the server
 * directly cannot pick its IP with it.
 */
export function clientIp(input: {
  remoteAddress: string | undefined;
  forwardedFor?: string | readonly string[] | null | undefined;
  trustedHops: TrustedHops;
  trustedHeader?: string | readonly string[] | null | undefined;
}): string | undefined {
  const hops = input.trustedHops;
  const remote = input.remoteAddress;

  const peerTrusted =
    typeof hops === 'number' ? hops > 0 : remote !== undefined && isTrustedAddress(remote, hops);

  const fromHeader = peerTrusted ? singleAddress(input.trustedHeader) : undefined;

  if (fromHeader !== undefined) return fromHeader;

  if (typeof hops !== 'number') {
    if (remote === undefined || !peerTrusted) return remote;

    // From the socket address leftwards, the first address outside the
    // trusted list is the client; when every one is trusted, the leftmost.
    const chain = headerList(input.forwardedFor).reverse();
    let client = remote;

    for (const address of chain) {
      client = address;

      if (!isTrustedAddress(address, hops)) break;
    }

    return client;
  }

  if (hops <= 0) return remote;

  const chain = headerList(input.forwardedFor);

  if (remote) chain.push(remote);
  if (chain.length === 0) return undefined;

  return chain[Math.max(0, chain.length - 1 - hops)];
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
