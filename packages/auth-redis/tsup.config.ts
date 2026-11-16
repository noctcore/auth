import { defineConfig } from 'tsup';

// Dual ESM and CommonJS output, each with its own declarations (.d.ts and
// .d.cts), because the apps that consume this package are CommonJS Nest builds
// and ESM tools alike.
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
});
