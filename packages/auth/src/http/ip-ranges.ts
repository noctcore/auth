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

interface Range {
  readonly bytes: Bytes;
  readonly prefix: number;
}

const V4 = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/u;
const GROUP = /^[0-9a-f]{1,4}$/iu;

function parseV4(text: string): Bytes | null {
  const match = V4.exec(text);

  if (!match) return null;

  const bytes = match.slice(1).map(Number);

  return bytes.every((b) => b <= 255) ? bytes : null;
}

function parseGroups(text: string): number[] | null {
  if (text === '') return [];

  const parts = text.split(':');
  const out: number[] = [];

  for (const [i, part] of parts.entries()) {
    // An IPv4 tail ("::ffff:192.0.2.1") counts as the last two groups.
    if (i === parts.length - 1 && part.includes('.')) {
      const v4 = parseV4(part);

      if (!v4) return null;

      out.push(((v4[0] ?? 0) << 8) | (v4[1] ?? 0), ((v4[2] ?? 0) << 8) | (v4[3] ?? 0));
      continue;
    }

    if (!GROUP.test(part)) return null;

    out.push(Number.parseInt(part, 16));
  }

  return out;
}

function parseV6(text: string): Bytes | null {
  const halves = text.split('::');

  if (halves.length > 2) return null;

  const head = parseGroups(halves[0] ?? '');
  const tail = halves.length === 2 ? parseGroups(halves[1] ?? '') : [];

  if (!head || !tail) return null;

  const missing = 8 - head.length - tail.length;

  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;

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

/** `::ffff:a.b.c.d` names the IPv4 address a.b.c.d; matched against IPv4 ranges as that. */
function unmapV4(bytes: Bytes): Bytes | null {
  if (bytes.length !== 16) return null;

  for (let i = 0; i < 10; i++) if (bytes[i] !== 0) return null;

  return bytes[10] === 0xff && bytes[11] === 0xff ? bytes.slice(12) : null;
}

function parseRange(entry: string): Range | null {
  const slash = entry.indexOf('/');
  const address = slash === -1 ? entry : entry.slice(0, slash);
  const bytes = parseIp(address);

  if (!bytes) return null;

  const max = bytes.length * 8;

  if (slash === -1) return { bytes, prefix: max };

  const prefixText = entry.slice(slash + 1);

  if (!/^(0|[1-9]\d{0,2})$/u.test(prefixText)) return null;

  const prefix = Number(prefixText);

  return prefix <= max ? { bytes, prefix } : null;
}

function inRange(bytes: Bytes, range: Range): boolean {
  if (bytes.length !== range.bytes.length) return false;

  let bits = range.prefix;

  for (let i = 0; bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;

    if (((bytes[i] ?? 0) & mask) !== ((range.bytes[i] ?? 0) & mask)) return false;
  }

  return true;
}

/**
 * Expands a trusted-proxy list into plain addresses and CIDR ranges: each
 * preset name becomes the ranges Express gives it, and every other entry
 * must be an IPv4 or IPv6 address or range. A string is split on commas, as
 * Express reads `trust proxy`. Refuses anything else at boot, so a typo never
 * quietly trusts nothing (or everything).
 */
export function resolveTrustedProxies(entries: string | readonly string[]): readonly string[] {
  const list = typeof entries === 'string' ? entries.split(',') : entries;
  const out: string[] = [];

  for (const raw of list) {
    const entry = raw.trim();

    if (Object.hasOwn(TRUST_PROXY_PRESETS, entry)) {
      out.push(...TRUST_PROXY_PRESETS[entry as TrustProxyPreset]);
      continue;
    }

    if (!parseRange(entry)) {
      throw new AuthConfigError(
        `Trusted proxy "${entry}" is not an IP address, a CIDR range or one of ${Object.keys(TRUST_PROXY_PRESETS).join(', ')}`,
      );
    }

    out.push(entry);
  }

  return Object.freeze(out);
}

const compiled = new WeakMap<readonly string[], readonly Range[]>();

function rangesOf(list: readonly string[]): readonly Range[] {
  const cached = compiled.get(list);

  if (cached) return cached;

  const ranges = resolveTrustedProxies(list).map((entry) => parseRange(entry) as Range);

  compiled.set(list, ranges);

  return ranges;
}

/** `a.b.c.d` as `::ffff:a.b.c.d`, for IPv6 ranges. */
function mapV4(bytes: Bytes): Bytes {
  return [...Array<number>(10).fill(0), 0xff, 0xff, ...bytes];
}

/**
 * True when the address is inside one of the trusted ranges (presets
 * allowed). An IPv4-mapped IPv6 address also matches the IPv4 ranges and a
 * plain IPv4 address the IPv6 ranges through its mapped form, as in Express.
 */
export function isTrustedAddress(address: string, list: readonly string[]): boolean {
  const bytes = parseIp(address);

  if (!bytes) return false;

  const other = bytes.length === 4 ? mapV4(bytes) : unmapV4(bytes);

  return rangesOf(list).some(
    (range) => inRange(bytes, range) || (other !== null && inRange(other, range)),
  );
}
