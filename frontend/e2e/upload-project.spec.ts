import { expect, test } from '@playwright/test';
import { fillZitadelLogin } from './helpers';

/**
 * Registering a project by direct upload, then actually scanning it.
 *
 * ⚠ THIS PROVES A BACKEND FIX, NOT JUST A FORM.
 *
 * Before it, a scan created with source_kind=upload always failed with
 * FETCH_NO_SOURCE: the orchestrator's fetch phase only ever read
 * project.repository_connections, and uploads were stored (and hashed) but
 * never wired to a scan at all. The wizard also had no upload branch — a
 * project registered for `upload` had no way to attach a file in the first
 * place. Both are what this test exercises: the form, AND that the resulting
 * scan actually reaches the engine-running phase instead of failing before a
 * single engine job is ever published.
 */

const USER = process.env['E2E_USER'] ?? 'alice@acme.test';
const PASSWORD = process.env['E2E_PASSWORD'] ?? 'AxeBOM-dev-only1!';

async function signIn(page: import('@playwright/test').Page, landing: string) {
  await page.goto(landing);
  await page.getByRole('button', { name: 'Log in' }).click();
  await fillZitadelLogin(page, USER, PASSWORD);
  await page.waitForURL(new RegExp(landing.replace('/', '\\/')), { timeout: 45_000 });
}

test('a project registered by upload reaches a real scan instead of FETCH_NO_SOURCE', async ({
  page,
}) => {
  test.setTimeout(120_000);

  const projectName = `e2e-upload-${Date.now()}`;

  await signIn(page, '/projects');

  // --- Register the project -------------------------------------------
  await page.goto('/projects/new');

  await page.getByLabel('Project name').fill(projectName);
  await page.getByRole('radio', { name: 'Upload' }).check();

  // A minimal but real manifest: syft/trivy-fs can resolve a dependency from
  // it without a lockfile, so the engines have something non-empty to report
  // rather than an immediate "nothing found" that would look identical to a
  // fetch that never happened.
  await page.getByLabel('Files').setInputFiles({
    name: 'package.json',
    mimeType: 'application/json',
    buffer: Buffer.from(
      JSON.stringify({ name: projectName, version: '1.0.0', dependencies: { lodash: '4.17.21' } }),
    ),
  });

  await expect(page.getByText('package.json')).toBeVisible();
  await page.getByRole('button', { name: 'Continue' }).click(); // -> owner & validity
  await page.getByRole('button', { name: 'Continue' }).click(); // -> classification & practices

  const createFailures: string[] = [];
  page.on('response', (r) => {
    if (r.url().includes('/api/v1/projects') && r.status() >= 400) {
      createFailures.push(`${r.status()} ${r.url()}`);
    }
  });

  await page.getByRole('button', { name: 'Create project' }).click();
  await page.waitForURL(/\/projects\/[0-9a-f-]+$/, { timeout: 15_000 });
  expect(createFailures, `project/upload requests that failed: ${createFailures.join(', ')}`).toEqual(
    [],
  );

  // --- Generate an SBOM from it ----------------------------------------
  await page.goto('/generate');

  const scanFailures: string[] = [];
  page.on('response', (r) => {
    if (r.url().includes('/api/v1/scans') && r.status() >= 400) {
      scanFailures.push(`${r.status()} ${r.url()}`);
    }
  });

  await page.getByRole('button', { name: new RegExp(projectName) }).first().click();
  await page.getByRole('button', { name: 'Continue' }).click(); // -> classification

  await page.getByRole('button', { name: /SBOM/ }).first().click();
  await page.getByRole('button', { name: 'Continue' }).click(); // -> report type

  await page.getByRole('button', { name: /Top-Level/i }).click();
  await page.getByRole('button', { name: 'Continue' }).click(); // -> standard

  await page.getByRole('button', { name: /SPDX 2\.3/i }).click();
  await page.getByRole('button', { name: 'Continue' }).click(); // -> format

  await page.getByRole('button', { name: /^JSON/ }).click();
  await page.getByRole('button', { name: 'Continue' }).click(); // -> review

  await expect(page.getByText(/could not start the scan/i)).toHaveCount(0);
  await page.getByRole('button', { name: /run and generate/i }).click();

  await page.waitForURL(/\/scans\/[0-9a-f-]+/, { timeout: 15_000 });
  expect(scanFailures, `scan requests that failed: ${scanFailures.join(', ')}`).toEqual([]);

  // --- The proof: an engine actually ran ------------------------------
  //
  // Before the fix, the fetch phase failed immediately with FETCH_NO_SOURCE
  // and no engine job was ever published — this table would sit at "No
  // engines have reported yet" until the reaper eventually failed the scan.
  // Reaching a real per-engine status here means the upload was found,
  // materialized and archived, and the orchestrator fanned out real work.
  await expect(page.getByRole('heading', { name: 'Scan progress' })).toBeVisible();
  await expect(page.getByText(/no engines have reported yet/i)).toHaveCount(0, { timeout: 60_000 });
  await expect(page.getByText('FETCH_NO_SOURCE')).toHaveCount(0);
});
