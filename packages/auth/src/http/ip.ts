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
 * expanded.
 */
export function resolveTrustedHops(value: TrustedHops, maxHops: number): TrustedHops {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || value > maxHops) {
      throw new AuthConfigError(
        `trustedHops must be a whole number of proxies from 0 to ${maxHops}, or a list of proxy addresses`,
      );
    }

    return value;
  }

  if (!Array.isArray(value)) {
    throw new AuthConfigError(
      'trustedHops must be a number of proxies or a list of proxy addresses and ranges',
    );
  }

  return resolveTrustedProxies(value);
}

const HEADER_NAME = /^[a-z0-9-]+$/u;

/**
 * Checks a `clientIpHeader` setting at boot and returns it lowercased.
 *
 * Refused unless `trustedHops` is a proxy list: a hop count never looks at
 * the socket address, so a client that reaches the server directly would be
 * taken for the edge and could write the header itself. Also refuses
 * `x-forwarded-for` (a list the hop rule already reads, never one address)
 * and anything that is not a header name.
 */
export function resolveClientIpHeader(
  name: string | undefined,
  trustedHops: TrustedHops,
): string | undefined {
  if (name === undefined) return undefined;

  const lower = String(name).trim().toLowerCase();

  if (!HEADER_NAME.test(lower)) throw new AuthConfigError(`Invalid client IP header name: ${name}`);

  if (!Array.isArray(trustedHops)) {
    throw new AuthConfigError(
      'clientIpHeader needs trustedHops as a list of your edge proxy addresses or ranges: with a hop count, a client that reaches the server directly could set the header',
    );
  }

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

/** A port as a proxy writes it: 1 to 65535, no leading zero. */
const PORT = /^[1-9]\d{0,4}$/u;

const isPort = (text: string): boolean => PORT.test(text) && Number(text) <= 65_535;

/**
 * One `X-Forwarded-For` entry as the address it names, or undefined when it
 * is not one. Some proxies write a port (`203.0.113.9:51234`,
 * `[2001:db8::1]:443`), brackets or an IPv6 zone id (`fe80::1%eth0`); those
 * are stripped, so a port that changes per connection never becomes part of
 * a rate-limit key. An unbracketed IPv6 address is taken whole: its last
 * group cannot be told apart from a port (`2001:db8::1:443` is itself a
 * valid address, so no rule can strip a port there without misreading one). Whatever is left must be exactly
 * one IPv4 or IPv6 address (an IPv4-mapped one included), as `isIp` reads it.
 */
function forwardedAddress(entry: string): string | undefined {
  let value = entry.trim();

  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    const rest = close === -1 ? '' : value.slice(close + 1);

    if (close === -1 || (rest !== '' && !(rest.startsWith(':') && isPort(rest.slice(1))))) {
      return undefined;
    }

    value = value.slice(1, close);

    // Brackets hold an IPv6 address only.
    if (!value.includes(':')) return undefined;
  } else {
    const colon = value.indexOf(':');

    // One colon: an IPv4 address with a port. Two or more: IPv6, taken whole.
    if (colon !== -1 && colon === value.lastIndexOf(':')) {
      if (!isPort(value.slice(colon + 1))) return undefined;

      value = value.slice(0, colon);
    }
  }

  const zone = value.indexOf('%');

  if (zone !== -1) {
    if (!value.includes(':')) return undefined;

    value = value.slice(0, zone);
  }

  return isIp(value) ? value : undefined;
}

/** The one address in a trusted header, or undefined when it is missing or not exactly one IP. */
function singleAddress(raw: string | readonly string[] | null | undefined): string | undefined {
  const [first, ...rest] = typeof raw === 'string' ? [raw] : (raw ?? []);

  if (first === undefined || rest.length > 0) return undefined;

  const value = first.trim();

  return isIp(value) ? value : undefined;
}

/**
 * The client IP given the socket address, the `X-Forwarded-For` header and
 * the trusted proxies. With 0 hops (or an empty list) the header is ignored.
 *
 * `trustedHeader` is the value of a single-address header your edge sets,
 * such as `cf-connecting-ip`. It wins only when `trustedHops` is a proxy
 * list, the socket address is inside it and the value is exactly one valid
 * IP; otherwise (a hop count included) it is ignored and the
 * `X-Forwarded-For` rule decides, so a client that reaches the server
 * directly cannot pick its IP with it. The list must name the edge itself,
 * or hops that accept traffic only from the edge.
 *
 * The `X-Forwarded-For` entry picked is read through `forwardedAddress`: a
 * port, brackets and an IPv6 zone id are stripped, and an entry that is still
 * not one IP is never returned. The socket address stands in for it, or
 * undefined when there is none, so a junk or per-connection entry never
 * becomes a rate-limit key or an audit value. An empty socket address counts
 * as none.
 */
export function clientIp(input: {
  remoteAddress: string | undefined;
  forwardedFor?: string | readonly string[] | null | undefined;
  trustedHops: TrustedHops;
  trustedHeader?: string | readonly string[] | null | undefined;
}): string | undefined {
  const hops = input.trustedHops;
  // An empty socket address names no peer: it is missing, in every branch.
  const remote = input.remoteAddress === '' ? undefined : input.remoteAddress;

  const peerTrusted =
    typeof hops === 'number' ? hops > 0 : remote !== undefined && isTrustedAddress(remote, hops);

  // A hop count never checks the socket, so the header needs a list.
  const fromHeader =
    peerTrusted && typeof hops !== 'number' ? singleAddress(input.trustedHeader) : undefined;

  if (fromHeader !== undefined) return fromHeader;

  if (typeof hops !== 'number') {
    if (remote === undefined || !peerTrusted) return remote;

    // From the socket address leftwards, the first address outside the
    // trusted list is the client; when every one is trusted, the leftmost.
    // An entry that is not an address is never trusted, so the walk stops
    // there and the socket address stands in for it.
    const chain = headerList(input.forwardedFor).reverse();
    let client: string | undefined = remote;

    for (const entry of chain) {
      client = forwardedAddress(entry);

      if (client === undefined || !isTrustedAddress(client, hops)) break;
    }

    return client ?? remote;
  }

  if (hops <= 0) return remote;

  // The socket address is the last proxy, so the client is `hops` entries
  // from the right of the header itself, with a socket address or without
  // one (a fetch adapter with no peer address). An entry picked from the
  // header must be an address, or the socket address stands in for it.
  const header = headerList(input.forwardedFor);
  const picked = header[Math.max(0, header.length - hops)];

  return picked === undefined ? remote : (forwardedAddress(picked) ?? remote);
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
