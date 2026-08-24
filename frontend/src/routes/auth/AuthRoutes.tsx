/**
 * The three screens the OIDC round trip needs.
 *
 * ⚠ /auth/callback AND /auth/silent ARE REGISTERED REDIRECT URIs.
 *
 * ZITADEL compares them byte for byte (libs/go-shared/iam/provision.go). If a
 * path here stops matching what `iam bootstrap` registered, the login fails
 * with a message that names neither the expected nor the received value — so
 * changing one means changing both.
 */

import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { initAuth } from '../../lib/auth';
import { useAuth } from '../../lib/useAuth';

/**
 * SignIn is what an unauthenticated visitor sees.
 *
 * Deliberately a button and not an automatic redirect. An app that bounces
 * straight to an identity provider cannot be looked at, cannot show why a
 * previous attempt failed, and turns a misconfigured client id into an endless
 * loop between two origins.
 */
export function SignIn() {
  const { signIn, error, loading } = useAuth();

  return (
    <div className="state state-empty">
      <h3 className="state-title">Sign in to EncoreBOM</h3>
      <p className="state-message">
        {error ?? 'You are signed out. EncoreBOM uses your organisation identity provider.'}
      </p>
      <div className="state-actions">
        <button className="btn btn-primary" onClick={signIn} disabled={loading}>
          Sign in
        </button>
      </div>
    </div>
  );
}

/**
 * NoAccess is a signed-in user with no role in this application.
 *
 * ⚠ A DISTINCT SCREEN, NOT A 403 ON EVERY REQUEST. ZITADEL authenticated them
 * perfectly; nobody granted them anything here. Without this the app renders
 * its full navigation and each screen fails on its own with
 * PERM_NO_ROLE_IN_ORG, which reads as a broken product rather than a missing
 * invitation — and leaves the user with no idea who to ask.
 */
export function NoAccess() {
  const { name, signOut } = useAuth();
  return (
    <div className="state state-empty">
      <h3 className="state-title">No access to EncoreBOM</h3>
      <p className="state-message">
        You are signed in as {name}, but your account has not been granted a role in any
        organisation of this application. Ask an administrator to invite you.
      </p>
      <div className="state-actions">
        <button className="btn" onClick={signOut}>
          Sign out
        </button>
      </div>
    </div>
  );
}

/** Callback completes the authorization-code exchange and returns the user home. */
export function AuthCallback() {
  const navigate = useNavigate();
  const [failure, setFailure] = useState<string | null>(null);

  // StrictMode mounts effects twice in development, and an authorization code
  // is single-use: the second exchange fails with `invalid_grant` and would
  // report a broken login for a session that actually succeeded.
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    // ⚠ await initAuth, NOT userManager(). React runs a child's effects before
    // its parent's, so this screen's effect fires BEFORE AuthProvider has built
    // the manager — reaching for it directly threw, and the throw looked like a
    // failed sign-in for a login that had actually worked.
    void initAuth()
      .then((mgr) => mgr.signinCallback())
      .then((user) => {
        const state = user?.state as { returnTo?: string } | undefined;
        const to = state?.returnTo;
        // Never navigate back to an absolute URL from the state: it round-trips
        // through the identity provider and is attacker-influenceable, which is
        // an open redirect. Only a same-site path is honoured.
        void navigate(to && to.startsWith('/') && !to.startsWith('//') ? to : '/projects', {
          replace: true,
        });
      })
      .catch((e: Error) => setFailure(e.message));
  }, [navigate]);

  if (failure) {
    return (
      <div className="state state-error">
        <h3 className="state-title">Sign-in did not complete</h3>
        <p className="state-message">{failure}</p>
        <div className="state-actions">
          <a className="btn" href="/">
            Start again
          </a>
        </div>
      </div>
    );
  }
  return <p className="state-message">Completing sign-in…</p>;
}

/**
 * SilentCallback runs inside the hidden renewal iframe.
 *
 * It must render essentially nothing and must not mount the application: the
 * iframe would otherwise boot a second React tree, fire its own queries, and
 * — because it is same-origin — race the parent's session storage.
 */
export function SilentCallback() {
  useEffect(() => {
    // Errors are swallowed on purpose: this frame has no user interface and
    // nobody can see a message in it. A failed renewal surfaces in the PARENT
    // through the silent-renew-error event, which AuthProvider listens for.
    void initAuth()
      .then((mgr) => mgr.signinSilentCallback())
      .catch(() => undefined);
  }, []);
  return null;
}
