import { expect, test } from '@playwright/test';

import { fillZitadelLogin } from './helpers';

/**
 * The registration wizard, reordered around the BOM type.
 *
 * ⚠ THE ORDER IS THE FEATURE. The wizard asked for the source on step 1 and the
 * classifications on step 3, so an incompatible pairing — an AIBOM project on a
 * url source, which no AIBOM engine can read — was only knowable on the last
 * screen, after the whole form was filled. Only a browser proves the reorder
 * actually narrows anything.
 */

const USER = process.env['E2E_USER'] ?? 'alice@acme.test';
const PASSWORD = process.env['E2E_PASSWORD'] ?? 'AxeBOM-dev-only1!';

test('BOM types are chosen first, and they narrow the sources offered', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Log in' }).click();
  await fillZitadelLogin(page, USER, PASSWORD);
  await page.waitForURL(/\/projects/, { timeout: 45_000 });

  await page.goto('/projects/new');

  // Step 1 is the BOM types, not the source.
  await expect(page.getByRole('heading', { name: 'What do you want to produce?' })).toBeVisible({
    timeout: 15_000,
  });

  const sbom = page.getByRole('checkbox', { name: 'SBOM' });
  const aibom = page.getByRole('checkbox', { name: 'AIBOM' });
  await expect(sbom).toBeChecked();

  // SBOM alone can be registered from a URL — webrecon reads exactly that.
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: /Where does this project come from/ })).toBeVisible();
  await expect(page.getByRole('radio', { name: 'Url' })).toBeVisible();

  // Adding AIBOM must remove it: no AIBOM engine reads a url source, and the
  // server refuses the combination.
  await page.getByRole('button', { name: 'Back' }).click();
  await aibom.check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('radio', { name: 'Url' })).toHaveCount(0);
  await expect(page.getByRole('radio', { name: 'Github' })).toBeVisible();
});

test('choosing QBOM without CBOM says what will be missing, and does not block it', async ({
  page,
}) => {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Log in' }).click();
  await fillZitadelLogin(page, USER, PASSWORD);
  await page.waitForURL(/\/projects/, { timeout: 45_000 });

  await page.goto('/projects/new');
  await expect(page.getByRole('heading', { name: 'What do you want to produce?' })).toBeVisible({
    timeout: 15_000,
  });

  await page.getByRole('checkbox', { name: 'QBOM' }).check();

  // ⚠ model.BOMType.IsDerived's own comment has always said this is "worth
  // warning about at registration rather than at report time". Nothing warned.
  await expect(page.getByText(/QBOM is derived from CBOM, and CBOM is not selected/)).toBeVisible();

  // Named, not refused: device metadata alone is a legitimate thing to want.
  await expect(page.getByRole('button', { name: 'Continue' })).toBeEnabled();

  // And the per-type task is stated before the project exists.
  await expect(page.getByRole('heading', { name: 'What these BOM types will need' })).toBeVisible();
  await expect(page.getByText(/Record the quantum device metadata/)).toBeVisible();
});
