import { defineConfig } from 'vitest/config';

// Unit tests and end-to-end tests against a real tRPC server (the fetch and
// the Node adapters, and nestjs-trpc on Express) with a real tRPC client,
// over the core's in-memory stores. No backends.
//
// `bun run test` runs with --coverage, and the thresholds fail the run when
// coverage drops. Every module here decides who gets through or what reaches
// the client, so all four sit at 100: add a test with the code, never lower
// one without saying why in the pull request.
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'json-summary'],
      thresholds: { lines: 100, branches: 100, functions: 100, statements: 100 },
    },
  },
});
