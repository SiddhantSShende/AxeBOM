/**
 * Who is signed in, which organisation they are acting in, and the token.
 *
 * ⚠ THIS IS THE ONLY PLACE THAT CALLS setAccessToken.
 *
 * The api client holds the token in a module-level slot precisely so no screen
 * has to thread it through props. That slot was never written to, which is why
 * every request went out unauthenticated. Writing it from one place — here, on
 * every user change — means a renewed token reaches the next request without a
 * re-render, and a signed-out session cannot leave a live token behind.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { User, UserManager } from 'oidc-client-ts';
import { AuthCtx, type AuthState } from './authState';
import { getOrgId, setAccessToken, setOrgId as setApiOrg, setTokenRefresher } from './api';
import {
  authConfig,
  displayName,
  initAuth,
  membershipsFrom,
  type AuthConfig,
  type Membership,
} from './auth';

/**
 * Where the chosen organisation is remembered across reloads.
 *
 * localStorage rather than session storage, and deliberately: this is a
 * preference, not a credential. Re-picking your employer in every new tab is
 * the kind of friction that makes a multi-tenant console tiring to use, and the
 * value grants nothing on its own — the server checks it against the roles the
 * token already carries.
 */
const ORG_KEY = 'encorebom.org';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [manager, setManager] = useState<UserManager | null>(null);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [orgId, setOrgIdState] = useState<string | null>(() => localStorage.getItem(ORG_KEY));

  // The token must be in place BEFORE any child renders and fires a query.
  // A state update would land a tick too late and the first request of every
  // session would 401 — intermittently, which is the worst kind.
  const apply = useCallback((u: User | null) => {
    setAccessToken(u?.access_token ?? null);
    setUser(u);
  }, []);

  // ------------------------------------------------------- bootstrap, once
  //
  // Configuration is fetched, so this is asynchronous and everything below
  // waits on it. The ref guard is what stops StrictMode's second mount from
  // probing twice; it must NOT guard anything that also has a cleanup — see
  // the next effect for why.
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;

    void initAuth()
      .then(async (mgr) => {
        setConfig(authConfig());
        setManager(mgr);
        // An expired user is not a user. oidc-client-ts returns the stored one
        // regardless, and treating it as signed in would put a dead token on
        // every request.
        const u = await mgr.getUser();
        apply(u && !u.expired ? u : null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [apply]);

  // ------------------------------------------- listeners, tied to the manager
  //
  // ⚠ A SEPARATE EFFECT, AND THAT IS A BUG FIX, NOT TIDINESS.
  //
  // Registering these inside the ref-guarded effect above meant StrictMode's
  // mount → cleanup → mount cycle REMOVED them and then skipped the re-add,
  // because the ref was already set. The result in development was a session
  // that authenticated correctly and then never saw another token: renewals
  // fired, `userLoaded` reached nobody, and the api client kept presenting the
  // token from fifteen minutes ago. This effect has no ref guard, so add and
  // remove stay symmetric however many times React runs it.
  useEffect(() => {
    if (!manager) return;

    const onLoaded = (u: User) => apply(u);
    const onUnloaded = () => apply(null);
    // A renewal that fails is a session that is about to break. Say so rather
    // than letting the next request return a bare 401.
    const onSilentError = (e: Error) => setError(`session renewal failed: ${e.message}`);

    manager.events.addUserLoaded(onLoaded);
    manager.events.addUserUnloaded(onUnloaded);
    manager.events.addSilentRenewError(onSilentError);

    // ⚠ THE API CLIENT RETRIES A 401 ONCE, AND THIS IS HOW IT GETS A TOKEN.
    //
    // Without it a request that outlives its token simply fails. `signinSilent`
    // uses the refresh token, so it does not bounce the user through a redirect
    // — and returning null on failure is what stops the retry looping.
    setTokenRefresher(async () => {
      try {
        const renewed = await manager.signinSilent();
        apply(renewed);
        return renewed?.access_token ?? null;
      } catch {
        apply(null);
        return null;
      }
    });

    return () => {
      setTokenRefresher(null);
      manager.events.removeUserLoaded(onLoaded);
      manager.events.removeUserUnloaded(onUnloaded);
      manager.events.removeSilentRenewError(onSilentError);
    };
  }, [manager, apply]);

  const memberships = useMemo<Membership[]>(
    () => (user && config ? membershipsFrom(user.profile, config.rolesClaim) : []),
    [user, config],
  );

  const activeOrg = useMemo(() => {
    if (memberships.length === 0) return null;
    return memberships.find((m) => m.orgId === orgId) ?? memberships[0] ?? null;
  }, [memberships, orgId]);

  // ⚠ SET DURING RENDER, NOT IN AN EFFECT.
  //
  // React runs a child's effects before its parent's, so the first screen to
  // mount fires its queries before an effect here could install the header. For
  // a user who belongs to one organisation that is invisible; for one who
  // belongs to two it is a first request answered AUTH_ORG_AMBIGUOUS and a
  // console that looks broken on load and fine on refresh.
  //
  // Writing a module-level slot is safe to do here: it is idempotent, sets no
  // state, and schedules no render.
  const wantOrg = activeOrg?.orgId ?? null;
  if (getOrgId() !== wantOrg) setApiOrg(wantOrg);

  const signIn = useCallback(() => {
    setError(null);
    // Come back to where the user actually was, not to the root.
    const returnTo = window.location.pathname + window.location.search;
    void initAuth()
      .then((mgr) => mgr.signinRedirect({ state: { returnTo } }))
      .catch((e: Error) => setError(e.message));
  }, []);

  const signOut = useCallback(() => {
    localStorage.removeItem(ORG_KEY);
    setAccessToken(null);
    setApiOrg(null);
    void initAuth()
      .then((mgr) => mgr.signoutRedirect())
      .catch((e: Error) => setError(e.message));
  }, []);

  const selectOrg = useCallback((next: string) => {
    localStorage.setItem(ORG_KEY, next);
    setOrgIdState(next);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      loading,
      user,
      name: user ? displayName(user) : '',
      memberships,
      activeOrg,
      error,
      signIn,
      signOut,
      selectOrg,
    }),
    [loading, user, memberships, activeOrg, error, signIn, signOut, selectOrg],
  );

  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}
