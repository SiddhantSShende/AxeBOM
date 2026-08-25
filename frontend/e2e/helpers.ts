import { expect, type Page } from '@playwright/test';

/**
 * Drives ZITADEL's hosted login UI: loginname, then password, each its own
 * step. Shared by auth.spec.ts (signing in as a seeded fixture) and
 * signup.spec.ts (signing in right after self-service signup creates the
 * account) — both land here once the app has redirected them to ZITADEL.
 */
export async function fillZitadelLogin(page: Page, email: string, password: string): Promise<void> {
  await step(page, /loginname|username|e-?mail/i, email, /next|continue/i);
  await step(page, /password/i, password, /next|continue|sign in|log ?in/i);
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
async function step(page: Page, label: RegExp, value: string, advance: RegExp): Promise<void> {
  const field = page.getByLabel(label);
  await field.waitFor({ state: 'visible' });
  const next = page.getByRole('button', { name: advance });

  await expect(async () => {
    await field.fill(value);
    await expect(next).toBeEnabled({ timeout: 1_000 });
  }).toPass({ timeout: 20_000 });

  await next.click();
}
