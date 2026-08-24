import { expect, test } from '@playwright/test';

/**
 * The login round trip.
 *
 * ⚠ THIS IS THE PATH THAT WAS COMPLETELY MISSING.
 *
 * The SPA had no authentication at all: `setAccessToken` existed with zero
 * callers, so every request went out with no `Authorization` header and every
 * screen rendered `no bearer token`. Unit tests could not have caught it —
 * each screen worked, and nothing tested the one thing nobody had written.
 *
 * It needs a real browser because the flow IS the browser: a redirect to
 * ZITADEL, a form post, a redirect back with an authorization code, and a PKCE
 * exchange. Every step is something curl can be made to fake and a user cannot.
 */

const USER = process.env['E2E_USER'] ?? 'alice@acme.test';
const PASSWORD = process.env['E2E_PASSWORD'] ?? 'EncoreBOM-dev-only1!';

async function signIn(page: import('@playwright/test').Page) {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Sign in' }).click();

  // ZITADEL's login UI: login name, then password, each on its own step.
  await step(page, /loginname|username|e-?mail/i, USER, /next|continue/i);
  await step(page, /password/i, PASSWORD, /next|continue|sign in|log ?in/i);

  await page.waitForURL(/\/projects/, { timeout: 45_000 });
}

/**
 * step fills one field of the login UI and advances.
 *
 * ⚠ THE FILL IS RETRIED, AND THAT IS NOT FLAKE-PAPERING.
 *
 * ZITADEL's login is a server-rendered Next.js page whose submit button stays
 * disabled until React sees a value. `fill` sets the DOM value and dispatches an
 * input event, so a fill that lands BEFORE hydration is silently discarded: the
 * text is visibly in the box and the button never enables. Playwright's own
 * click retry cannot rescue that — it waited a full minute on a control that was
 * never going to change — because the missing event already happened.
 *
 * Retrying the fill itself is the fix: once hydration completes, one more fill
 * registers and the button enables immediately.
 */
async function step(
  page: import('@playwright/test').Page,
  label: RegExp,
  value: string,
  advance: RegExp,
) {
  const field = page.getByLabel(label);
  await field.waitFor({ state: 'visible' });
  const next = page.getByRole('button', { name: advance });

  await expect(async () => {
    await field.fill(value);
    await expect(next).toBeEnabled({ timeout: 1_000 });
  }).toPass({ timeout: 20_000 });

  await next.click();
}

test('an anonymous visitor is asked to sign in rather than shown an error', async ({ page }) => {
  await page.goto('/projects');

  // ⚠ NOT `no bearer token`. That string was the symptom: the app rendered its
  // data screens, fired queries with no credential, and showed the API's
  // rejection as though the user had done something wrong.
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  await expect(page.getByText(/no bearer token/i)).toHaveCount(0);
});

test('signing in reaches the projects list with real data', async ({ page }) => {
  await signIn(page);

  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
  await expect(page.getByText(/no bearer token/i)).toHaveCount(0);

  // The seed gives Acme two projects. Asserting on one of them proves the token
  // was not merely present but ACCEPTED, resolved to a tenant, and that RLS let
  // the row through — a signed-in user with a bad tenant claim sees an empty
  // list, which looks like success.
  await expect(page.getByText('payments-api').first()).toBeVisible();
});

test('the session survives a reload without another redirect', async ({ page }) => {
  await signIn(page);
  await page.reload();

  // A reload that bounces back to the identity provider means the session was
  // never restored, and every refresh would cost a full round trip.
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toHaveCount(0);
});

test('the header names who is signed in and offers a way out', async ({ page }) => {
  await signIn(page);

  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
});
