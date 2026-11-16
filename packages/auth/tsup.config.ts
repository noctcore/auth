import { defineConfig } from 'tsup';

// Dual ESM and CommonJS output, each with its own declarations (.d.ts and
// .d.cts), because the apps that consume this package are CommonJS Nest builds
// (often tested under Jest, which cannot require an ES module) and ESM tools
// alike.
//
// The @oslojs primitives are ES modules only, so they are bundled into both
// outputs rather than required at runtime: the published package then has no
// runtime dependencies at all. @node-rs/argon2 stays external; it is an
// optional peer that only the /argon2 entry imports.
export default defineConfig({
  entry: { index: 'src/index.ts', argon2: 'src/argon2.ts', testing: 'src/testing/index.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  noExternal: [/^@oslojs\//],
  external: ['@node-rs/argon2'],
});
