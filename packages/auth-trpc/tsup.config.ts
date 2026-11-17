import { defineConfig } from 'tsup';

// Dual ESM and CommonJS output, each with its own declarations (.d.ts and
// .d.cts), because tRPC servers (and nestjs-trpc apps) are CommonJS and ESM
// builds alike.
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
});
