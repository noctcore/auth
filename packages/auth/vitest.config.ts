import { defineConfig } from 'vitest/config';

// Fast unit tests: no network, no real backends.
//
// `bun run test` runs with --coverage, and the thresholds below fail the run
// when coverage drops. They sit at or just under what the suite reaches today:
// raise them when tests are added, and never lower one without saying why in
// the pull request. The modules that decide who is signed in (crypto, tokens,
// session, throttle, password) and the plugins (two-factor) are held at 100 percent; http and the flows just
// under it. A focused run (`bunx vitest run tests/core`) skips coverage.
//
// Nothing is excluded. The one branch no test can reach is the `?? ''` after
// `split('::')[0]` in http/ip.ts (`split` always returns at least one element),
// which noUncheckedIndexedAccess requires.
const FULL = { lines: 100, branches: 100, functions: 100, statements: 100 };

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['tests/**/*.int.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text-summary', 'json-summary'],
      thresholds: {
        lines: 98,
        branches: 96,
        functions: 97,
        statements: 98,
        'src/crypto/**': FULL,
        'src/tokens/**': FULL,
        'src/session/**': FULL,
        'src/throttle/**': FULL,
        'src/password/**': FULL,
        'src/plugins/**': FULL,
        'src/http/**': { lines: 100, branches: 99, functions: 100, statements: 99 },
        'src/flows/**': { lines: 99, branches: 95, functions: 97, statements: 98 },
      },
    },
  },
});
