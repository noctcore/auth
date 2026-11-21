/**
 * Durations for the Learn diagrams, read from the same values the code
 * samples in snippets/learn/ show. scripts/learn-numbers.test.ts checks those
 * samples against the package source, so a changed default redraws the
 * diagram and fails the test until the sample follows.
 *
 * The package's own parser is not imported: the site builds without building
 * the packages, and this needs only the units the samples use.
 */
const UNIT_MS = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const;

export function toMs(duration: string): number {
  const match = /^(\d+)([smhd])$/u.exec(duration);

  if (!match) throw new Error(`duration: cannot read "${duration}"`);

  return Number(match[1]) * UNIT_MS[match[2] as keyof typeof UNIT_MS];
}

/** "5 min", "1 h", "24 h", "30 d": the short form the diagrams print. */
export function shortDuration(ms: number): string {
  if (ms < UNIT_MS.m * 2) return `${ms / UNIT_MS.s} s`;
  if (ms % UNIT_MS.d === 0 && ms >= UNIT_MS.d * 2) return `${ms / UNIT_MS.d} d`;
  if (ms % UNIT_MS.h === 0) return `${ms / UNIT_MS.h} h`;
  if (ms % UNIT_MS.m === 0) return `${ms / UNIT_MS.m} min`;

  return `${ms / UNIT_MS.s} s`;
}

/** 1 → "1st", 6 → "6th", 11 → "11th". */
export function ordinal(n: number): string {
  const teen = n % 100 >= 11 && n % 100 <= 13;
  const suffix = teen ? 'th' : ({ 1: 'st', 2: 'nd', 3: 'rd' } as Record<number, string>)[n % 10];

  return `${n}${suffix ?? 'th'}`;
}
