import { expect, test } from '@playwright/test';

import { fillZitadelLogin } from './helpers';

/**
 * The GitHub connection panel in Settings.
 *
 * ⚠ THE WIZARD TOLD PEOPLE TO COME HERE BEFORE THIS EXISTED. Its copy on the
 * already-connected path reads "Disconnect from Settings to revoke it", and no
 * such control existed anywhere — the endpoints were used only by the
 * registration screen. An instruction pointing at a screen that is not there is
 * worse than no instruction: it reads as the reader's failure to find it.
 */

const USER = process.env['E2E_USER'] ?? 'alice@acme.test';
const PASSWORD = process.env['E2E_PASSWORD'] ?? 'AxeBOM-dev-only1!';

test('settings has a GitHub panel that states the connection state', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Log in' }).click();
  await fillZitadelLogin(page, USER, PASSWORD);
  await page.waitForURL(/\/projects/, { timeout: 45_000 });

  await page.goto('/settings');
  const panel = page.getByRole('region', { name: 'GitHub' });
  await expect(panel).toBeVisible({ timeout: 15_000 });

  // Whichever state the organisation is in, the panel must SAY which — a panel
  // that renders nothing is the same dead end the wizard's copy pointed at.
  await expect(panel).toContainText(/Not connected|Connected as/);
});
