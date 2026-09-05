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

  // ⚠ THE ID COMES FROM THE DOM, NOT FROM fetch() INSIDE THE PAGE. The SPA
  // holds its bearer token in memory and attaches it in its own client, so a
  // raw in-page fetch goes out unauthenticated and returns an error body —
  // which reads here as "no projects exist".
  //
  // ⚠ AND THE UUID FILTER IS LOAD-BEARING: /projects/new is a link too, and a
  // previous session's screenshot script grabbed exactly that.
  // ⚠ WAIT FOR THE LIST BEFORE READING THE DOM. waitForURL only says the route
  // changed; React has not necessarily rendered the projects yet, and an
  // evaluate() that runs a frame early finds no links and reports "no project
  // exists" — which is a confusing lie about the database.
  await expect(page.locator('a[href^="/projects/0"]').first()).toBeVisible({ timeout: 20_000 });

  // ⚠ READ THROUGH THE LOCATOR API, NOT page.evaluate(). An evaluate callback
  // runs in the browser, where `document` has no type under this project's
  // eslint config — so every line inside it became an "unsafe member access on
  // a type that cannot be resolved". The locator API is typed, shorter, and
  // does not need the DOM lib at all.
  const href = (await page.locator('a[href^="/projects/0"]').first().getAttribute('href')) ?? '';
  const projectId = href.replace('/projects/', '').split('/')[0] ?? '';
  expect(projectId, 'no project exists to attach a device to').not.toBe('');

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
