// The fast-check parameters every property test shares. A fixed seed keeps a
// normal run reproducible, so a red CI run is red again on a laptop; the
// nightly fuzz job sets FC_SEED and a large FC_NUM_RUNS to search further.
// fast-check prints the seed and the counterexample path when a property
// fails, so any failure (fixed seed or not) can be replayed with FC_SEED.
import type { Parameters } from 'fast-check';

const DEFAULT_SEED = 20_261_117;
const DEFAULT_NUM_RUNS = 200;

function parse(name: string, given: string | undefined, fallback: number): number {
  const raw = given?.trim();

  if (!raw) return fallback;

  const value = Number(raw);

  if (!Number.isSafeInteger(value)) throw new Error(`${name} must be an integer, got ${raw}`);

  return value;
}

/** `{ seed, numRuns }` for `fc.assert`, overridable with FC_SEED and FC_NUM_RUNS. */
export function runs<T>(): Parameters<T> {
  return {
    seed: parse('FC_SEED', process.env['FC_SEED'], DEFAULT_SEED),
    numRuns: parse('FC_NUM_RUNS', process.env['FC_NUM_RUNS'], DEFAULT_NUM_RUNS),
  };
}
