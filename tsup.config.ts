import { defineConfig } from 'tsup';

export default defineConfig([
  // Library build: ESM + CJS for npm consumers (Vue, React, Node)
  {
    entry: { index: 'src/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'es2020',
    outExtension({ format }) {
      return { js: format === 'cjs' ? '.cjs' : '.js' };
    },
  },
  // CLI build: ESM with a shebang, suitable for `npx @smoker_winston/egov-helper`
  {
    entry: { cli: 'src/cli/index.ts' },
    format: ['esm'],
    sourcemap: true,
    target: 'es2020',
    platform: 'node',
    banner: { js: '#!/usr/bin/env node' },
    outExtension: () => ({ js: '.mjs' }),
  },
  // Standalone browser bundle: drop into Razor / MVC / static HTML via <script>
  {
    entry: { 'egov-helper': 'src/index.ts' },
    format: ['iife'],
    globalName: 'EgovHelper',
    minify: true,
    sourcemap: true,
    target: 'es2020',
    outExtension: () => ({ js: '.min.js' }),
    noExternal: ['node-forge'],
    platform: 'browser',
  },
]);
