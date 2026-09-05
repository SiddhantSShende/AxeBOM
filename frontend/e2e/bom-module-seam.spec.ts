import { expect, test } from '@playwright/test';

import { fillZitadelLogin } from './helpers';

/**
 * The BOM-module seam, driven through the real API.
 *
 * ⚠ WHAT THIS PROVES THAT A GO TEST CANNOT: the options endpoint really serves
 * the per-type source lists to a browser, and the running service really
 * refuses the two combinations it now claims to. The Go tests call the service
 * directly; this goes through the handler, the router and the auth middleware.
 */

const USER = process.env['E2E_USER'] ?? 'alice@acme.test';
const PASSWORD = process.env['E2E_PASSWORD'] ?? 'AxeBOM-dev-only1!';
const APP_ORIGIN = process.env['E2E_BASE_URL'] ?? 'http://localhost:5173';

test('the options endpoint publishes per-BOM-type sources, and the server enforces them', async ({
  page,
}) => {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Log in' }).click();
  await fillZitadelLogin(page, USER, PASSWORD);
  await page.waitForURL(/\/projects/, { timeout: 45_000 });
  await expect(page.locator('a[href^="/projects/0"]').first()).toBeVisible({ timeout: 20_000 });

  // ⚠ CAPTURED FROM A REAL REQUEST, NOT READ OUT OF STORAGE. Reaching into
  // sessionStorage means a page.evaluate callback, where `window` has no type
  // under this project's eslint config — every line inside it becomes an
  // "unsafe member access on a type that cannot be resolved", which is the
  // trap device-register.spec.ts already documents. Taking the header off a
  // request the SPA actually sent is typed, shorter, and tests the token the
  // browser really uses rather than one this test re-derived.
  //
  // ⚠ THE WAIT IS ARMED BEFORE THE NAVIGATION THAT SATISFIES IT. The SPA's
  // first authenticated calls already went out during login, so waiting after
  // the fact would hang until the timeout on a page that is doing nothing.
  const pending = page.waitForRequest(
    (req) => req.url().includes('/api/v1/') && req.headers()['authorization'] !== undefined,
    { timeout: 20_000 },
  );
  await page.reload();
  const authHeader = (await pending).headers()['authorization'];
  expect(authHeader, 'no authenticated API request was observed').toBeTruthy();
  const token = (authHeader ?? '').replace(/^Bearer /, '');

  const api = async (path: string, init?: RequestInit) => {
    // ⚠ THROUGH /api ON THE APP ORIGIN, exactly as lib/api.ts does. The SPA
    // never calls the gateway directly: vite.config.ts proxies /api to it in
    // development and nginx does the same in production. Hitting the gateway
    // port here would test a path no browser uses.
    const res = await page.request.fetch(`${APP_ORIGIN}/api${path}`, {
      method: init?.method ?? 'GET',
      headers: { Authorization: `Bearer ${token ?? ''}`, 'Content-Type': 'application/json' },
      ...(init?.body ? { data: init.body } : {}),
    });
    return { status: res.status(), body: (await res.json()) as Record<string, unknown> };
  };

  const options = await api('/v1/projects/options');
  expect(options.status).toBe(200);

  const bomTypes = options.body['bom_types'] as Array<{ id: string; sources: string[] }>;
  const byID = new Map(bomTypes.map((t) => [t.id, t.sources]));

  // Every type must publish a non-empty list, or the wizard cannot narrow.
  for (const [id, sources] of byID) {
    expect(sources, `${id} publishes no sources`).not.toHaveLength(0);
  }

  // The two facts the seam exists to state.
  expect(byID.get('AIBOM'), 'no AIBOM engine reads a url source').not.toContain('url');
  expect(byID.get('HBOM'), 'manual is HBOM first-class path').toContain('manual');
  expect(byID.get('SBOM'), 'no form produces a component inventory').not.toContain('manual');

  // And the server refuses what it declines to offer.
  const refused = await api('/v1/projects', {
    method: 'POST',
    body: JSON.stringify({
      name: `seam-probe-${Date.now()}`,
      source_type: 'url',
      classifications: ['AIBOM'],
    }),
  });
  expect(refused.status, 'an AIBOM project was accepted from a url source').toBe(422);
});
