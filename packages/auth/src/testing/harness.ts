/**
 * Runner-agnostic conformance cases. A suite is a list of named async cases
 * that assert with `node:assert`, so the same cases run under Vitest, Jest or
 * node:test: hand `runConformance` your runner's `describe` and `it`.
 */
export interface ConformanceCase {
  readonly name: string;
  run(): Promise<void>;
}

export interface TestApi {
  describe(name: string, body: () => void): void;
  it(name: string, body: () => Promise<void>, timeout?: number): void;
}

export interface ConformanceContext {
  /**
   * Moves time forward for the store. Real backends sleep (the default); a
   * store built on an injectable clock advances it instead.
   */
  readonly advanceTime?: (ms: number) => Promise<void>;
}

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export function runConformance(
  title: string,
  cases: readonly ConformanceCase[],
  api: TestApi,
  timeout = 20_000,
): void {
  api.describe(title, () => {
    for (const testCase of cases) api.it(testCase.name, () => testCase.run(), timeout);
  });
}

/** A unique id per call, so cases on a shared real backend never collide. */
export function uniqueId(prefix: string): string {
  const bytes = new Uint8Array(8);

  globalThis.crypto.getRandomValues(bytes);

  return `${prefix}_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export function times<T>(count: number, fn: (index: number) => Promise<T>): Promise<T[]> {
  return Promise.all(Array.from({ length: count }, (_, i) => fn(i)));
}
