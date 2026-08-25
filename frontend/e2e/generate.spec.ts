import { expect, test } from '@playwright/test';

/**
 * The Generate wizard's "Run" action.
 *
 * ⚠ THIS REPRODUCES A REPORTED BUG: `POST /v1/scans` 422'd with
 * "request body is not valid JSON" (VALIDATION_BODY_MALFORMED) on every
 * submission. The wizard was posting bom_types/levels/standards/formats to an
 * endpoint whose Go struct only knows project_id/source_kind/families/engines
 * and rejects unknown fields outright (json.Decoder.DisallowUnknownFields).
 */

async function signIn(page: import('@playwright/test').Page) {
  await page.goto('/generate');
  await page.getByRole('button', { name: 'Sign in' }).click();
  const l = page.getByLabel(/loginname|username|e-?mail/i);
  await l.waitFor();
  await l.fill('alice@acme.test');
  await page.waitForTimeout(400);
  await page.getByRole('button', { name: /next|continue/i }).click();
  const p = page.getByLabel(/password/i);
  await p.waitFor();
  await p.fill('AxeBOM-dev-only1!');
  await page.waitForTimeout(400);
  await page.getByRole('button', { name: /next|continue|sign in|log ?in/i }).click();
  await page.waitForURL(/\/generate/, { timeout: 45000 });
}

test('the generate wizard creates a scan and queues its reports without a 422', async ({
  page,
}) => {
  const failures: string[] = [];
  page.on('response', (r) => {
    if (r.url().includes('/api/v1/scans') && r.status() >= 400) {
      failures.push(`${r.status()} ${r.url()}`);
    }
  });

  await signIn(page);

  // Step 1 — project.
  await page.getByRole('button', { name: /payments-api/i }).first().click();
  await page.getByRole('button', { name: 'Continue' }).click();

  // Step 2 — classification.
  await page.getByRole('button', { name: /SBOM/ }).first().click();
  await page.getByRole('button', { name: 'Continue' }).click();

  // Step 3 — report type.
  await page.getByRole('button', { name: /Top-Level/i }).click();
  await page.getByRole('button', { name: 'Continue' }).click();

  // Step 4 — standard.
  await page.getByRole('button', { name: /SPDX 2\.3/i }).click();
  await page.getByRole('button', { name: 'Continue' }).click();

  // Step 5 — format.
  await page.getByRole('button', { name: /^JSON/ }).click();
  await page.getByRole('button', { name: 'Continue' }).click();

  // Step 6 — review, then run.
  await expect(page.getByText(/could not start the scan/i)).toHaveCount(0);
  await page.getByRole('button', { name: /run and generate/i }).click();

  await page.waitForURL(/\/scans\/[0-9a-f-]+/, { timeout: 15000 });

  expect(failures, `scan/report requests that failed: ${failures.join(', ')}`).toEqual([]);
  await expect(page.getByRole('heading', { name: 'Scan progress' })).toBeVisible();
});
