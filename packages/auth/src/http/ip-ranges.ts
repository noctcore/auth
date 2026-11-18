/**
 * IP addresses and CIDR ranges, for trusting proxies by address instead of by
 * hop count.
 *
 * Parsing is strict on purpose: these strings come from configuration and
 * from headers, and a lenient parser (octal octets, zone ids, ports) is where
 * two components start disagreeing about which address a string names.
 */
import { AuthConfigError } from '../shared/errors';

/**
 * The trust-proxy preset names Express accepts, with the ranges it resolves
 * them to (Express "behind proxies" guide, implemented by `proxy-addr`).
 */
export const TRUST_PROXY_PRESETS = {
  loopback: ['127.0.0.1/8', '::1/128'],
  linklocal: ['169.254.0.0/16', 'fe80::/10'],
  uniquelocal: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'],
} as const satisfies Record<string, readonly string[]>;

export type TrustProxyPreset = keyof typeof TRUST_PROXY_PRESETS;

/** A parsed address: 4 bytes for IPv4, 16 for IPv6. */
type Bytes = readonly number[];

/** A range as its family (byte count), prefix length and masked network bytes. */
interface Range {
  readonly length: number;
  readonly prefix: number;
  readonly network: string;
}

const V4 = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/u;
const GROUP = /^[0-9a-f]{1,4}$/iu;

function parseV4(text: string): [number, number, number, number] | null {
  const match = V4.exec(text);

  if (!match) return null;

  const [, a, b, c, d] = match.map(Number) as [number, number, number, number, number];

  return a <= 255 && b <= 255 && c <= 255 && d <= 255 ? [a, b, c, d] : null;
}

/**
 * The 16-bit groups of one side of an IPv6 address. `endsAddress` is true
 * only for the part that ends the whole address: an IPv4 tail
 * ("::ffff:192.0.2.1") is allowed there and nowhere else, so "1.2.3.4::" and
 * "1:1.2.3.4::5" are refused, as Node refuses them.
 */
function parseGroups(text: string, endsAddress: boolean): number[] | null {
  if (text === '') return [];

  const parts = text.split(':');
  const out: number[] = [];

  for (const [i, part] of parts.entries()) {
    // An IPv4 tail counts as the last two groups.
    if (endsAddress && i === parts.length - 1 && part.includes('.')) {
      const v4 = parseV4(part);

      if (!v4) return null;

      const [a, b, c, d] = v4;

      out.push((a << 8) | b, (c << 8) | d);
      continue;
    }

    if (!GROUP.test(part)) return null;

    out.push(Number.parseInt(part, 16));
  }

  return out;
}

function parseV6(text: string): Bytes | null {
  const gap = text.indexOf('::');

  // At most one "::" (":::" counts as two).
  if (gap !== text.lastIndexOf('::')) return null;

  const head = parseGroups(gap === -1 ? text : text.slice(0, gap), gap === -1);
  const tail = gap === -1 ? [] : parseGroups(text.slice(gap + 2), true);

  if (!head || !tail) return null;

  const missing = 8 - head.length - tail.length;

  if (gap === -1 ? missing !== 0 : missing < 1) return null;

  const groups = [...head, ...Array<number>(missing).fill(0), ...tail];

  return groups.flatMap((g) => [g >> 8, g & 0xff]);
}

/** The bytes of an IPv4 or IPv6 address, or null when the text is not exactly one. */
export function parseIp(text: string): Bytes | null {
  return text.includes(':') ? parseV6(text) : parseV4(text);
}

/** True when the text is exactly one IPv4 or IPv6 address. */
export function isIp(text: string): boolean {
  return parseIp(text) !== null;
}

const MAPPED_PREFIX = '0.0.0.0.0.0.0.0.0.0.255.255';

/** `::ffff:a.b.c.d` (16 bytes) names the IPv4 address a.b.c.d; matched against IPv4 ranges as that. */
function unmapV4(bytes: Bytes): Bytes | null {
  return bytes.slice(0, 12).join('.') === MAPPED_PREFIX ? bytes.slice(12) : null;
}

/** The bytes with every bit past the prefix cleared, as a comparable string. */
function masked(bytes: Bytes, prefix: number): string {
  return bytes
    .map((byte, i) => {
      const bits = Math.min(8, Math.max(0, prefix - i * 8));

      return byte & ((0xff << (8 - bits)) & 0xff);
    })
    .join('.');
}

function parseRange(entry: string): Range | null {
  const slash = entry.indexOf('/');
  const address = slash === -1 ? entry : entry.slice(0, slash);
  const bytes = parseIp(address);

  if (!bytes) return null;

  const max = bytes.length * 8;
  const prefixText = slash === -1 ? String(max) : entry.slice(slash + 1);

  if (!/^(0|[1-9]\d{0,2})$/u.test(prefixText)) return null;

  const prefix = Number(prefixText);

  if (prefix > max) return null;

  return { length: bytes.length, prefix, network: masked(bytes, prefix) };
}

function inRange(bytes: Bytes, range: Range): boolean {
  return bytes.length === range.length && masked(bytes, range.prefix) === range.network;
}

/** `a.b.c.d` as `::ffff:a.b.c.d`, for IPv6 ranges. */
function mapV4(bytes: Bytes): Bytes {
  return [...Array<number>(10).fill(0), 0xff, 0xff, ...bytes];
}

/**
 * A range that holds every address of a family: `0.0.0.0/0`, `::/0`, or an
 * IPv6 range that holds all of `::ffff:0:0/96` (every IPv4 address matches it
 * through its mapped form). Trusting one is trusting every hop, which is what
 * refusing `true` is for.
 */
function holdsEverything(range: Range): boolean {
  return (
    range.prefix === 0 ||
    (range.length === 16 && range.prefix <= 96 && inRange(mapV4([0, 0, 0, 0]), range))
  );
}

const PRESET_NAMES = Object.keys(TRUST_PROXY_PRESETS).join(', ');

/**
 * Each entry with its presets expanded and its range parsed, or the reason
 * the first bad entry is refused. Never throws.
 */
function compile(
  entries: readonly unknown[],
): { readonly entries: string[]; readonly ranges: Range[] } | { readonly refused: string } {
  const out: string[] = [];
  const ranges: Range[] = [];

  for (const raw of entries) {
    if (typeof raw !== 'string') return { refused: 'Trusted proxy entries must be strings' };

    const entry = raw.trim();

    const expanded: readonly string[] = Object.hasOwn(TRUST_PROXY_PRESETS, entry)
      ? TRUST_PROXY_PRESETS[entry as TrustProxyPreset]
      : [entry];

    for (const item of expanded) {
      const range = parseRange(item);

      if (!range) {
        return {
          refused: `Trusted proxy "${entry}" is not an IP address, a CIDR range or one of ${PRESET_NAMES}`,
        };
      }

      if (holdsEverything(range)) {
        return {
          refused: `Trusted proxy "${entry}" trusts every address, so any client could choose its own IP; list your proxies`,
        };
      }

      out.push(item);
      ranges.push(range);
    }
  }

  return { entries: out, ranges };
}

/**
 * Expands a trusted-proxy list into plain addresses and CIDR ranges: each
 * preset name becomes the ranges Express gives it, and every other entry
 * must be an IPv4 or IPv6 address or range. A string is split on commas, as
 * Express reads `trust proxy`. Refuses anything else at boot, so a typo never
 * quietly trusts nothing (or everything).
 */
export function resolveTrustedProxies(entries: string | readonly string[]): readonly string[] {
  const list: readonly unknown[] = typeof entries === 'string' ? entries.split(',') : entries;
  const result = compile(Array.isArray(list) ? list : [list]);

  if ('refused' in result) throw new AuthConfigError(result.refused);

  return Object.freeze(result.entries);
}

const compiled = new WeakMap<object, readonly Range[]>();

/**
 * The ranges of a trusted list, compiled once per list. On the request path
 * this never throws: a list that does not compile (or is not a list) trusts
 * nothing, so a misconfigured direct caller fails closed. `resolveTrustedHops`
 * and `resolveTrustedProxies` refuse the same list loudly at boot.
 */
function rangesOf(list: unknown): readonly Range[] {
  if (!Array.isArray(list)) return [];

  const cached = compiled.get(list);

  if (cached) return cached;

  const result = compile(list);
  const ranges = 'refused' in result ? [] : result.ranges;

  compiled.set(list, ranges);

  return ranges;
}

/**
 * True when the address is inside one of the trusted ranges (presets
 * allowed). An IPv4-mapped IPv6 address also matches the IPv4 ranges and a
 * plain IPv4 address the IPv6 ranges through its mapped form, as in Express.
 * An IPv6 zone id (`fe80::1%eth0`, as a socket reports a link-local peer) is
 * dropped first. Never throws: a list that does not compile trusts nothing.
 */
export function isTrustedAddress(address: string, list: readonly string[]): boolean {
  if (typeof address !== 'string') return false;

  const zone = address.indexOf('%');
  const bytes = parseIp(zone > 0 && address.includes(':') ? address.slice(0, zone) : address);

  if (!bytes) return false;

  const other = bytes.length === 4 ? mapV4(bytes) : unmapV4(bytes);

  return rangesOf(list).some(
    (range) => inRange(bytes, range) || (other !== null && inRange(other, range)),
  );
}
