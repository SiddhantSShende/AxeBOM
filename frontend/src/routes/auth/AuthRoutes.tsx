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
import { Link, useNavigate } from 'react-router';
import { AuthShell } from '../../components/AuthShell';
import { initAuth } from '../../lib/auth';
import { useAuth } from '../../lib/useAuth';

/**
 * SignIn is what an unauthenticated visitor sees: a choice between two real
 * destinations, not an automatic redirect to either one.
 *
 * ⚠ TWO BUTTONS, NOT ONE PLUS A FOOTNOTE — AND NOT AN AUTO-REDIRECT.
 *
 * A visitor here is either RETURNING (wants Sign in) or NEW (wants Create
 * your organisation), and there is no single destination to auto-navigate to
 * that serves both — auto-redirecting straight to ZITADEL, tried briefly,
 * meant the sign-up path was unreachable: the browser had already left this
 * screen before anyone could click it. Showing both choices here also keeps
 * the property that mattered about the auto-redirect attempt in the first
 * place: a misconfigured client id or an unreachable gateway fails visibly,
 * via `error` below, on a click — never as a silent bounce between origins
 * with nothing on screen to read.
 */
export function SignIn() {
  const { signIn, error, loading } = useAuth();

  return (
    <AuthShell>
      <div className="auth-card-body">
        <h3 className="state-title">Log in to AxeBOM</h3>
        <p className="state-message">
          {error ?? 'You are signed out. AxeBOM uses your organisation identity provider.'}
        </p>
        <div className="state-actions">
          {/* Not `onClick={signIn}` — the DOM click event would flow into
              signIn's optional `returnTo` parameter as if it were a string. */}
          <button className="btn btn-primary" onClick={() => signIn()} disabled={loading}>
            Log in
          </button>
          <Link className="btn" to="/signup">
            Create your account
          </Link>
        </div>
      </div>
    </AuthShell>
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
    <AuthShell>
      <div className="auth-card-body">
        <h3 className="state-title">No access to AxeBOM</h3>
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
    </AuthShell>
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
      <AuthShell className="auth-card-error">
        <div className="auth-card-body">
          <h3 className="state-title">Sign-in did not complete</h3>
          <p className="state-message">{failure}</p>
          <div className="state-actions">
            <a className="btn" href="/">
              Start again
            </a>
          </div>
        </div>
      </AuthShell>
    );
  }
  return (
    <AuthShell>
      <p className="auth-card-body state-message">Completing sign-in…</p>
    </AuthShell>
  );
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
