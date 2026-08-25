import { expect, test } from '@playwright/test';
import { fillZitadelLogin } from './helpers';

/**
 * The self-service "create your organisation" round trip.
 *
 * ⚠ THIS IS THE PATH THAT REPLACES ZITADEL'S OWN (DISABLED) REGISTRATION.
 *
 * ZITADEL's hosted "Register new user" link is turned off
 * (libs/go-shared/iam.ensureLoginPolicy) because a self-registered user holds
 * a role in no organisation and the OIDC callback refuses to complete. This
 * spec proves the replacement actually closes that gap end to end: the form
 * creates the organisation and its Owner through POST /v1/auth/signup, and
 * the visitor can then sign in to it immediately — not "the API returned
 * 201", which a unit test could already tell us, but "ZITADEL's real login
 * screen accepts the password just set and the app shows real data after".
 *
 * A fresh org name and email per run (Date.now()): AUTH_ORG_NAME_TAKEN /
 * AUTH_EMAIL_TAKEN are exercised by services/gateway/internal/signup's own
 * unit-testable logic, not by colliding with a previous run here.
 */

test('creating an organisation reaches the projects list with a real role', async ({ page }) => {
  const stamp = Date.now();
  const org = `E2E Signup Org ${stamp}`;
  const email = `e2e-signup-${stamp}@example.test`;
  const password = 'E2ESignup-1!';

  await page.goto('/signup');

  await page.getByLabel(/organisation name/i).fill(org);
  await page.getByLabel(/first name/i).fill('E2E');
  await page.getByLabel(/last name/i).fill('Signup');
  await page.getByLabel(/^email$/i).fill(email);
  await page.getByLabel(/^password/i).fill(password);
  await page.getByRole('button', { name: /create organisation/i }).click();

  // The redirect to ZITADEL only fires once POST /v1/auth/signup has
  // answered 201 — waiting for the loginname field is what actually proves
  // the account was created, not merely that the button was clicked.
  await fillZitadelLogin(page, email, password);

  await page.waitForURL(/\/projects/, { timeout: 45_000 });

  // The account this run just created is Owner of a brand-new organisation
  // with zero projects — "Projects" heading with no PERM_NO_ROLE_IN_ORG
  // screen is what proves ensureProjectGrant + ensureAuthorization actually
  // ran, not just ensureOrg.
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
  await expect(page.getByText(/no access to axebom/i)).toHaveCount(0);
});

test('signing up with an organisation name already in use is refused, not merged', async ({
  page,
}) => {
  const stamp = Date.now();
  const org = `E2E Dup Org ${stamp}`;

  await page.goto('/signup');
  await page.getByLabel(/organisation name/i).fill(org);
  await page.getByLabel(/first name/i).fill('First');
  await page.getByLabel(/last name/i).fill('Owner');
  await page.getByLabel(/^email$/i).fill(`e2e-dup-a-${stamp}@example.test`);
  await page.getByLabel(/^password/i).fill('E2ESignup-1!');
  await page.getByRole('button', { name: /create organisation/i }).click();
  await page.waitForURL(/\/ui\/v2\/login/, { timeout: 20_000 });

  // Back to the form, deliberately, without completing the ZITADEL login —
  // this test is about the SECOND signup being refused, not about the first
  // one finishing.
  await page.goto('/signup');
  await page.getByLabel(/organisation name/i).fill(org);
  await page.getByLabel(/first name/i).fill('Second');
  await page.getByLabel(/last name/i).fill('Visitor');
  await page.getByLabel(/^email$/i).fill(`e2e-dup-b-${stamp}@example.test`);
  await page.getByLabel(/^password/i).fill('E2ESignup-1!');
  await page.getByRole('button', { name: /create organisation/i }).click();

  // ⚠ STILL ON /signup, NOT REDIRECTED. A visitor who lands at ZITADEL's
  // login here would be about to authenticate into somebody else's
  // organisation — the exact failure iam.Signup's non-idempotent semantics
  // exist to prevent (see the doc comment on iam.ErrOrgNameTaken).
  await expect(page.getByText(/already exists/i)).toBeVisible();
  await expect(page).toHaveURL(/\/signup/);
});
