/**
 * Durations in configuration. A bare number is SECONDS, a string carries its
 * unit: `'15m'`, `'1h'`, `'30d'`. One parser so a TTL can never be read as
 * milliseconds in one place and seconds in another.
 */
export type Duration = number | `${number}${'ms' | 's' | 'm' | 'h' | 'd'}`;

const UNIT_MS = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const;
const PATTERN = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/u;

export function toMilliseconds(duration: Duration): number {
  let ms: number;
  if (typeof duration === 'number') {
    ms = duration * 1000;
  } else {
    const match = PATTERN.exec(duration);
    if (!match) throw new TypeError(`Invalid duration: ${JSON.stringify(duration)}`);
    ms = Number(match[1]) * UNIT_MS[match[2] as keyof typeof UNIT_MS];
  }
  if (!Number.isFinite(ms) || ms < 0) throw new TypeError(`Invalid duration: ${String(duration)}`);
  return Math.round(ms);
}

/** Whole seconds, rounded up so a TTL is never shorter than asked for. */
export function toSeconds(duration: Duration): number {
  return Math.ceil(toMilliseconds(duration) / 1000);
}
