import { defineConfig } from '@playwright/test';

/**
 * End-to-end tests against the RUNNING STACK, not a dev server.
 *
 * ⚠ NO `webServer`. These exercise the login round trip, which needs ZITADEL,
 * the gateway and every service — `task dev`, in other words. A config that
 * span up `vite dev` on its own would test a frontend talking to nothing and
 * pass while the deployed article was broken, which is exactly the failure
 * these tests exist to catch.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL: process.env['E2E_BASE_URL'] ?? 'http://localhost:5173',
    trace: 'retain-on-failure',
  },
});
