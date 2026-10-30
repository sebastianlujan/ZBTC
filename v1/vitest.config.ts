import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // snarkjs spawns worker threads for the curve; forks isolate them per test file.
    pool: 'forks',
    testTimeout: 300_000,
    hookTimeout: 300_000,
  },
});
