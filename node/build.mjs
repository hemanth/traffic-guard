import * as esbuild from 'esbuild';

const sharedConfig = {
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  target: 'node20',
  sourcemap: true,
  external: ['@typesafe-ai/sdk', 'node:*']
};

await Promise.all([
  // ESM build
  esbuild.build({
    ...sharedConfig,
    format: 'esm',
    outfile: 'dist/index.mjs'
  }),
  // CJS build
  esbuild.build({
    ...sharedConfig,
    format: 'cjs',
    outfile: 'dist/index.cjs'
  })
]);

console.log('Build complete: dist/index.mjs & dist/index.cjs');
