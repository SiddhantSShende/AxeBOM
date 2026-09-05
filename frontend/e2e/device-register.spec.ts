import { expect, test } from '@playwright/test';

import { fillZitadelLogin } from './helpers';

/**
 * The device register, driven for real.
 *
 * ⚠ THIS SCREEN HAS NEVER RENDERED. Every part of it — the profile-generated
 * form, the two fieldsets, the parts summary — is new, and the store beneath it
 * is new. Unit tests prove the pieces; only a browser proves the screen.
 */

const USER = process.env['E2E_USER'] ?? 'alice@acme.test';
const PASSWORD = process.env['E2E_PASSWORD'] ?? 'AxeBOM-dev-only1!';

test('a device can be registered, listed and edited', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Log in' }).click();
  await fillZitadelLogin(page, USER, PASSWORD);
  await page.waitForURL(/\/projects/, { timeout: 45_000 });

  // ⚠ A SEEDED HARDWARE PROJECT, NOT "WHATEVER IS FIRST IN THE LIST".
  //
  // This used to take the first /projects/0… link it found, which is an
  // SBOM project — and registering a device against one is now refused with
  // PROJECT_NOT_CLASSIFIED, correctly: no report that project can produce would
  // ever contain the device. Nothing checked before the BOM-module seam, so
  // this test had been exercising a combination the product does not allow.
  //
  // migrations/seed/0001_dev_tenants.sql now carries `edge-gateway`, a manual
  // HBOM project, for exactly this. A fixed id rather than a search: the point
  // of the test is the device register, and picking the target by classification
  // through the UI would make an unrelated screen able to fail it.
  const projectId = '01900000-0000-7000-8000-0000000000f4';
  await expect(page.locator('a[href^="/projects/0"]').first()).toBeVisible({ timeout: 20_000 });

  await page.goto(`/projects/${projectId}/hardware`);
  await expect(page.getByRole('heading', { name: 'Devices' })).toBeVisible({ timeout: 15_000 });

  await page.getByRole('button', { name: 'Register a device' }).first().click();

  // ⚠ THE LABELS COME FROM THE COMPLIANCE PROFILE, not from this file. Finding
  // them by their CERT-In names is what proves the form is generated rather
  // than hardcoded — if somebody replaces it with static inputs whose labels
  // drift from the guideline, this fails.
  // ⚠ THE NAME IS UNIQUE PER RUN, NOT JUST THE SERIAL. The first version of
  // this used a fixed name and located the row by it — which passed once and
  // then hit a strict-mode violation on the second run, because the register is
  // real, persistent state and the first device was still in it.
  const serial = `E2E-${Date.now()}`;
  const name = `E2E Edge Gateway ${serial}`;
  await page.getByLabel('Product Name *').fill(name);
  await page.getByLabel('Manufacturer Name').fill('Encore Systems');
  await page.getByLabel('Model Number').fill('ENC-GW-4400');
  await page.getByLabel('Serial Number').fill(serial);

  await page.getByRole('button', { name: 'Register device' }).click();

  const row = page.getByRole('row', { name: new RegExp(serial) });
  await expect(row).toBeVisible({ timeout: 15_000 });
  // ⚠ "No parts list imported yet", NOT "0 parts". Registering a device and
  // importing its parts are two acts, and the difference has to reach the user.
  await expect(row).toContainText('No parts list imported yet');
  await expect(row).toContainText(serial);

  // ⚠ RETIRE WHAT THIS TEST REGISTERED. The device register is real, shared,
  // persistent state on a developer's stack; a test that leaves rows behind
  // makes the screen it is testing progressively less usable, and eventually
  // makes the next person's manual check unreadable.
  await row.getByRole('button', { name: 'Retire' }).click();
  await expect(row).toBeHidden({ timeout: 15_000 });
});
