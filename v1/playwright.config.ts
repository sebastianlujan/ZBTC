// UI integration tests: the real wallet page, driven by real pointer and keyboard input,
// against the real server, CLI and a regtest node of their own (test/ui/env.ts).
import { defineConfig } from '@playwright/test';
import { HTTP_PORT, RPC_PORT, STATE_DIR } from './test/ui/env.js';

export default defineConfig({
  testDir: 'test/ui',
  // Not *.test.ts or *.spec.ts, so vitest never picks these up.
  testMatch: '**/*.ui.ts',
  // One chain and one browser page: the tests run in order and build on each other.
  workers: 1,
  fullyParallel: false,
  // Shielded transfers prove in zero knowledge, which takes seconds.
  timeout: 180_000,
  expect: { timeout: 90_000 },
  reporter: [['list']],
  globalSetup: './test/ui/setup.ts',
  globalTeardown: './test/ui/teardown.ts',
  use: {
    baseURL: `http://127.0.0.1:${HTTP_PORT}`,
    // The installed Chrome, so no browser download is needed.
    channel: 'chrome',
    viewport: { width: 1440, height: 900 },
    trace: 'retain-on-failure',
  },
  webServer: {
    // One node process (tsx as a loader, not a wrapper that forks), so stopping it leaves no orphan.
    command: 'node --import tsx ui/server.ts',
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    url: `http://127.0.0.1:${HTTP_PORT}/app.js`,
    env: { PORT: String(HTTP_PORT), RPCPORT: String(RPC_PORT), ZBTC_UI_STATE: STATE_DIR },
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
