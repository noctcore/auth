// The measuring half of the wall-clock timing benchmarks: command-line knobs,
// a seeded shuffle, trimmed statistics and Welch's t. benchmark.ts uses it on
// the in-memory stores; examples/basic/tests/timing.ts on Postgres and Redis.
//
// Each comparison runs its two arms in a shuffled order (from the seed) so
// drift and garbage collection land on both alike, drops the slowest 5
// percent of each arm, and reports the medians and Welch's t. A |t| under
// 4.5 (the threshold dudect uses) means this run could not tell the arms
// apart.
import type { RequestMeta } from '../../src';

const THRESHOLD = 4.5;

function arg(name: string, fallback: number): number {
  const index = process.argv.indexOf(`--${name}`);
  const value = index === -1 ? undefined : Number(process.argv[index + 1]);

  return value !== undefined && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

/** `--samples` per arm (default 100) and `--seed` for the shuffle (default 20261117). */
export const SAMPLES = arg('samples', 100);
export const SEED = arg('seed', 20_261_117);

/** mulberry32: a small seeded generator, so a run's order can be replayed. */
function seeded(seed: number): () => number {
  let state = seed >>> 0;

  return () => {
    state = (state + 0x6d2b79f5) >>> 0;

    let t = state;

    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);

    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

const random = seeded(SEED);
let ipCounter = 0;

/** A fresh client address per request, so the per-IP door limit never answers first. */
export function meta(): RequestMeta {
  ipCounter += 1;

  return { ip: `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter & 255}` };
}

async function time(run: () => Promise<unknown>): Promise<number> {
  const start = process.hrtime.bigint();

  await run();

  return Number(process.hrtime.bigint() - start) / 1e6;
}

interface Stats {
  median: number;
  mean: number;
  variance: number;
  n: number;
}

function stats(samples: number[]): Stats {
  const kept = [...samples].sort((a, b) => a - b).slice(0, Math.ceil(samples.length * 0.95));
  const mean = kept.reduce((sum, x) => sum + x, 0) / kept.length;
  const variance = kept.reduce((sum, x) => sum + (x - mean) ** 2, 0) / Math.max(kept.length - 1, 1);

  return { median: kept[Math.floor(kept.length / 2)] ?? 0, mean, variance, n: kept.length };
}

function welch(a: Stats, b: Stats): number {
  const spread = Math.sqrt(a.variance / a.n + b.variance / b.n);

  return spread === 0 ? 0 : (a.mean - b.mean) / spread;
}

export interface Comparison {
  name: string;
  arms: readonly [label: string, run: (i: number) => Promise<unknown>][];
}

/** Times both arms in a shuffled order and prints the result; true when they cannot be told apart. */
export async function compare({ name, arms }: Comparison): Promise<boolean> {
  const order = arms.flatMap((_, arm) => Array.from({ length: SAMPLES }, (__, i) => ({ arm, i })));

  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));

    [order[i], order[j]] = [order[j] ?? { arm: 0, i: 0 }, order[i] ?? { arm: 0, i: 0 }];
  }

  // Warm up both paths (JIT, Argon2's first allocation, connection pools) before measuring.
  for (const [, run] of arms) for (let i = 0; i < 5; i++) await run(-1 - i);

  const samples: number[][] = arms.map(() => []);

  for (const { arm, i } of order) {
    const [, run] = arms[arm] ?? arms[0] ?? ['', () => Promise.resolve()];

    samples[arm]?.push(await time(() => run(i)));
  }

  const [a, b] = samples.map(stats) as [Stats, Stats];
  const t = welch(a, b);
  const same = Math.abs(t) < THRESHOLD;
  const label = (index: number) => arms[index]?.[0] ?? '';

  console.log(`\n${name}`);

  console.log(
    `  ${label(0).padEnd(34)} median ${a.median.toFixed(3)} ms   mean ${a.mean.toFixed(3)} ms`,
  );

  console.log(
    `  ${label(1).padEnd(34)} median ${b.median.toFixed(3)} ms   mean ${b.mean.toFixed(3)} ms`,
  );

  console.log(
    `  Welch t = ${t.toFixed(2)}  ${same ? 'not distinguishable' : 'DISTINGUISHABLE'} at |t| < ${THRESHOLD}`,
  );

  return same;
}

/** The closing line of a run: how many comparisons were told apart, and how to replay it. */
export function summarize(results: readonly boolean[]): void {
  const distinguishable = results.filter((same) => !same).length;

  console.log(
    `\n${distinguishable} of ${results.length} comparisons distinguishable. Replay with --seed ${SEED} --samples ${SAMPLES}.`,
  );
}
