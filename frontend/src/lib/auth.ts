/**
 * OIDC authentication against ZITADEL.
 *
 * ⚠ THE SPA HAD NO AUTHENTICATION AT ALL.
 *
 * `setAccessToken` existed with zero callers, so every request went out with no
 * `Authorization` header and every screen rendered `no bearer token`. The
 * services had already moved to ZITADEL; the browser had not moved anywhere.
 *
 * # Authorization Code with PKCE, and no client secret
 *
 * A browser cannot keep a secret. Shipping one in a bundle is worse than having
 * none, because it looks like security. The application is registered as
 * USER_AGENT + AUTH_METHOD_NONE, which is exactly this flow
 * (libs/go-shared/iam/provision.go).
 *
 * # Configuration is FETCHED, not compiled in
 *
 * The client id and project id are produced by `axebom iam bootstrap` and
 * differ per ZITADEL instance. Baking them into the bundle would mean one
 * frontend image per environment, rebuilt whenever identity is re-provisioned —
 * and the deployed image has no build args at all, so the compiled-in value was
 * the empty string and login was impossible in the very stack it shipped to.
 *
 * They come from GET /api/v1/auth/config instead (services/gateway/internal/
 * authconfig), which costs one small request at startup and is correct in every
 * environment. The VITE_ variables below remain as a local override for running
 * `npm run dev` against something other than the gateway.
 *
 * # The access token lives in memory
 *
 * `userStore` is session storage — per tab, gone when the tab closes — and the
 * ACCESS TOKEN is pushed into the api client's in-memory slot and read from
 * there. Anything JavaScript can read from disk, an XSS can exfiltrate.
 */

import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts';

/** AuthConfig is what the gateway publishes, and everything the SPA needs. */
export interface AuthConfig {
  issuer: string;
  clientId: string;
  projectId: string;
  scopes: string[];
  /** The ZITADEL claim carrying this project's role grants. */
  rolesClaim: string;
  /** The claim naming the organisation that owns the user record. */
  orgClaim: string;
  /** The request header that selects an organisation. */
  orgHeader: string;
}

interface ConfigDocument {
  issuer: string;
  client_id: string;
  project_id: string;
  scopes: string[];
  roles_claim: string;
  org_claim: string;
  org_header: string;
}

/**
 * ⚠ THE ISSUER IS THIS ORIGIN, NOT ZITADEL'S OWN ADDRESS.
 *
 * nginx (and the vite dev proxy) serve ZITADEL's canonical paths from
 * http://localhost:5173 so there is one origin, one issuer, no CORS on the
 * token endpoint and a same-site redirect. ZITADEL bakes the issuer into every
 * token, and a client that discovers a different one rejects every token it is
 * given.
 */
function overrideFromEnv(): AuthConfig | null {
  const clientId = import.meta.env.VITE_OIDC_CLIENT_ID;
  const projectId = import.meta.env.VITE_OIDC_PROJECT_ID;
  if (!clientId || !projectId) return null;
  return {
    issuer: import.meta.env.VITE_OIDC_ISSUER || window.location.origin,
    clientId,
    projectId,
    scopes: defaultScopes(projectId),
    rolesClaim: `urn:zitadel:iam:org:project:${projectId}:roles`,
    orgClaim: 'urn:zitadel:iam:user:resourceowner:id',
    orgHeader: 'X-AxeBOM-Org',
  };
}

/**
 * The scope set used only by the local override.
 *
 * ⚠ THE AUDIENCE SCOPE IS NOT OPTIONAL. `oidcauth.Verifier` checks that the
 * project id appears in the token's `aud`, because op.VerifyAccessToken
 * validates the signature, issuer and clock but NOT that the token was minted
 * for us — without that check any token from any other application on the same
 * instance would be accepted. ZITADEL only adds the project to the audience
 * when this scope is requested, so omitting it produces a token that verifies
 * cryptographically and is refused as "not issued for this application".
 *
 * In every real deployment the list comes from the server, so this stays a
 * fallback and cannot drift into being a second source of truth.
 */
function defaultScopes(projectId: string): string[] {
  return [
    'openid',
    'profile',
    'email',
    'offline_access',
    `urn:zitadel:iam:org:project:id:${projectId}:aud`,
  ];
}

let config: AuthConfig | null = null;
let manager: UserManager | null = null;
let starting: Promise<UserManager> | null = null;

/**
 * initAuth fetches configuration and builds the UserManager, once.
 *
 * ⚠ IDEMPOTENT, AND EVERY ENTRY POINT AWAITS IT. React runs effects
 * child-first, so the callback screens mount and run their effects BEFORE the
 * provider that wraps them does — a manager built only by the provider would
 * not exist yet at the moment the authorization code needs exchanging. Sharing
 * one promise means the several callers race harmlessly instead of building
 * several managers with several state stores.
 */
export function initAuth(): Promise<UserManager> {
  starting ??= start();
  return starting;
}

async function start(): Promise<UserManager> {
  config = overrideFromEnv() ?? (await fetchConfig());
  manager = build(config);
  return manager;
}

async function fetchConfig(): Promise<AuthConfig> {
  const res = await fetch('/api/v1/auth/config', { credentials: 'same-origin' });
  if (!res.ok) {
    // Surface the server's own message: when identity is unprovisioned it names
    // the command that fixes it, which is more use than "request failed".
    let detail = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: { message?: string } };
      if (body.error?.message) detail = body.error.message;
    } catch {
      /* a non-JSON body means a proxy answered, not a service */
    }
    throw new Error(`identity configuration unavailable: ${detail}`);
  }
  const doc = (await res.json()) as ConfigDocument;
  return {
    issuer: doc.issuer,
    clientId: doc.client_id,
    projectId: doc.project_id,
    scopes: doc.scopes,
    rolesClaim: doc.roles_claim,
    orgClaim: doc.org_claim,
    orgHeader: doc.org_header,
  };
}

function build(cfg: AuthConfig): UserManager {
  const origin = window.location.origin;
  return new UserManager({
    authority: cfg.issuer,
    client_id: cfg.clientId,
    // ⚠ MUST MATCH THE REGISTERED URIs EXACTLY. ZITADEL compares redirect URIs
    // byte for byte — a trailing slash or a different port is a rejected login
    // whose message names neither the expected nor the received value.
    redirect_uri: `${origin}/auth/callback`,
    post_logout_redirect_uri: `${origin}/`,
    silent_redirect_uri: `${origin}/auth/silent`,
    response_type: 'code',
    scope: cfg.scopes.join(' '),

    // Renew ahead of expiry so a long session never interrupts work. Access
    // tokens live fifteen minutes, so this fires about four times an hour.
    automaticSilentRenew: true,
    accessTokenExpiringNotificationTimeInSeconds: 120,

    // ⚠ SESSION STORAGE, NOT LOCAL. Per tab, and gone when the tab closes,
    // which bounds how long a refresh token an XSS could reach stays useful.
    // localStorage would survive a browser restart and be readable by every
    // tab on the origin.
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),

    // ⚠ TRUE, BECAUSE ZITADEL PUTS NO PROFILE CLAIMS IN EITHER TOKEN.
    //
    // Measured against this instance: with `openid profile email` requested,
    // the id and access tokens carry sub, aud, the roles claim and nothing
    // else — no name, no email, no preferred_username. Without this call the
    // header greets the user by their ZITADEL subject, a nineteen-digit number.
    //
    // The ROLES still come from the token, not from here. This adds a display
    // name, not an authorisation input, so a userinfo response that is slow or
    // missing degrades the greeting rather than the session.
    loadUserInfo: true,
  });
}

/**
 * userManager returns the built manager.
 *
 * Throws before initAuth has resolved. Callers that can run early — the two
 * callback screens — await initAuth instead.
 */
export function userManager(): UserManager {
  if (!manager) throw new Error('userManager used before initAuth resolved');
  return manager;
}

/** authConfig is the resolved configuration, or null before initAuth resolves. */
export function authConfig(): AuthConfig | null {
  return config;
}

export type Role = 'owner' | 'admin' | 'analyst' | 'viewer';

/** Membership is one organisation the signed-in user holds a role in. */
export interface Membership {
  orgId: string;
  orgDomain: string;
  role: Role;
}

/**
 * ⚠ ROLE PRECEDENCE, NOT FIRST MATCH.
 *
 * ZITADEL's roles claim is `{role: {orgId: domain}}`, so one organisation can
 * appear under several roles. Taking the first would make the result depend on
 * object key order — a user granted both `viewer` and `admin` in one tenant is
 * an admin. Mirrors oidcauth.Verifier, which does the same on the server.
 *
 * Exported (not just used internally) because `roleAtLeast` needs the same
 * ordering, and a second, hand-typed list is how the two definitions drift.
 */
export const ROLE_PRECEDENCE: Role[] = ['viewer', 'analyst', 'admin', 'owner'];
const precedence = ROLE_PRECEDENCE;

/**
 * roleAtLeast mirrors libs/go-shared/authz.RoleAtLeast.
 *
 * ⚠ THIS IS A UX CONVENIENCE, NOT ENFORCEMENT. Hiding a control a Viewer
 * cannot use saves them a round trip to a 403; it does not replace the
 * server's own check, which is what actually protects the resource. Never
 * ship a control gated ONLY by this that has no matching matrix row.
 */
export function roleAtLeast(actual: Role | null | undefined, want: Role): boolean {
  if (!actual) return false;
  return precedence.indexOf(actual) >= precedence.indexOf(want);
}

export function membershipsFrom(
  profile: Record<string, unknown>,
  rolesClaim: string,
): Membership[] {
  const raw = profile[rolesClaim];
  if (!raw || typeof raw !== 'object') return [];

  const best = new Map<string, Membership>();
  for (const [role, orgs] of Object.entries(raw as Record<string, unknown>)) {
    if (!precedence.includes(role as Role)) continue;
    if (!orgs || typeof orgs !== 'object') continue;

    for (const [orgId, domain] of Object.entries(orgs as Record<string, string>)) {
      const candidate: Membership = { orgId, orgDomain: String(domain), role: role as Role };
      const held = best.get(orgId);
      if (!held || precedence.indexOf(candidate.role) > precedence.indexOf(held.role)) {
        best.set(orgId, candidate);
      }
    }
  }
  return [...best.values()].sort((a, b) => a.orgDomain.localeCompare(b.orgDomain));
}

/** displayName prefers a real name and falls back to something identifying. */
export function displayName(user: User): string {
  const p = user.profile as Record<string, unknown>;
  return (
    (typeof p['name'] === 'string' && p['name']) ||
    (typeof p['email'] === 'string' && p['email']) ||
    user.profile.sub
  );
}
