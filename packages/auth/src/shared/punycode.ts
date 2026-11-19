/**
 * Punycode decoding (RFC 3492), so the unicode email policy can check that
 * the URL parser's ASCII form of a domain maps back to exactly the labels
 * that were typed. UTS 46 processing maps some characters onto others (an
 * ideographic full stop onto a dot, a Greek iota subscript onto an iota), and
 * an address whose domain it would remap is a second spelling of a host that
 * other addresses spell differently. Written here rather than imported from
 * `node:url` so the core stays free of Node built-ins.
 */

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 0x7fffffff;

function adapt(delta: number, points: number, first: boolean): number {
  let d = first ? Math.floor(delta / DAMP) : delta >> 1;
  let k = 0;

  d += Math.floor(d / points);

  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }

  return Math.floor(k + ((BASE - T_MIN + 1) * d) / (d + SKEW));
}

function digitOf(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 22;
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x61;

  return BASE;
}

/** Decodes the part of a label after `xn--`; null when it is not valid Punycode. */
export function decodePunycode(input: string): string | null {
  const basic = Math.max(input.lastIndexOf('-'), 0);
  const output: number[] = [];

  for (let j = 0; j < basic; j++) {
    const code = input.charCodeAt(j);

    if (code >= 0x80) return null;

    output.push(code);
  }

  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;

  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const old = i;
    let w = 1;

    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) return null;

      const digit = digitOf(input.charCodeAt(index++));

      if (digit >= BASE || digit > Math.floor((MAX_INT - i) / w)) return null;

      i += digit * w;

      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;

      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) return null;

      w *= BASE - t;
    }

    const points = output.length + 1;

    bias = adapt(i - old, points, old === 0);

    if (Math.floor(i / points) > MAX_INT - n) return null;

    n += Math.floor(i / points);
    i %= points;

    if (n > 0x10ffff) return null;

    output.splice(i++, 0, n);
  }

  return String.fromCodePoint(...output);
}
