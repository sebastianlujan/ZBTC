import { defineConfig } from 'vitest/config';

/** Generous limit for the regtest end-to-end suite, which mines blocks and waits on Core. */
const TEST_TIMEOUT_MS = 300_000;

export default defineConfig({
  test: {
    testTimeout: TEST_TIMEOUT_MS,
    hookTimeout: TEST_TIMEOUT_MS,
  },
});
