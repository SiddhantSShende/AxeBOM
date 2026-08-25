/**
 * The self-service "create your organisation" form.
 *
 * ⚠ WHY THIS EXISTS: ZITADEL's own hosted "Register new user" link is turned
 * OFF (libs/go-shared/iam.ensureLoginPolicy) because a user created that way
 * holds a role in NO organisation, and the OIDC callback then refuses to
 * complete. This form is the flow that replaces it — it creates the
 * ORGANISATION and its first user, as Owner, through
 * POST /v1/auth/signup (services/gateway/internal/signup) BEFORE handing the
 * visitor to ZITADEL's password screen, so by the time they reach it there is
 * a role waiting for them.
 *
 * Mounted at the top level in App.tsx, outside <Shell> and outside
 * RequireAuth — exactly like /auth/callback: this is how a visitor with no
 * session yet REACHES one, so it cannot be gated behind having one already.
 */

import { useState, type ChangeEvent, type FormEvent } from 'react';
import { Link } from 'react-router';
import { AuthShell } from '../../components/AuthShell';
import { api, ApiError } from '../../lib/api';
import { useAuth } from '../../lib/useAuth';

interface Draft {
  organisationName: string;
  givenName: string;
  familyName: string;
  email: string;
  password: string;
}

const EMPTY_DRAFT: Draft = {
  organisationName: '',
  givenName: '',
  familyName: '',
  email: '',
  password: '',
};

export function SignupPage() {
  const { signIn } = useAuth();
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // A separate flag from `submitting`: once the account exists, the only
  // thing left to do is redirect to ZITADEL, and re-showing the form while
  // that redirect is in flight would let a second submit try to create the
  // same organisation twice.
  const [created, setCreated] = useState(false);

  function field(key: keyof Draft) {
    return {
      value: draft[key],
      onChange: (e: ChangeEvent<HTMLInputElement>) =>
        setDraft((d) => ({ ...d, [key]: e.target.value })),
    };
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post('/v1/auth/signup', {
        organisation_name: draft.organisationName.trim(),
        email: draft.email.trim(),
        password: draft.password,
        given_name: draft.givenName.trim(),
        family_name: draft.familyName.trim(),
      });
      setCreated(true);
      // '/projects', not the default (current path): signIn() with no
      // argument returns to wherever the browser already is, which is this
      // form — redirecting a freshly created visitor right back to it would
      // look like the account was never made.
      signIn('/projects');
    } catch (err) {
      setSubmitting(false);
      setError(err instanceof ApiError ? err.message : 'Could not create the organisation');
    }
  }

  if (created) {
    return (
      <AuthShell>
        <div className="auth-card-body">
          <h3 className="state-title">Account created</h3>
          <p className="state-message">Taking you to sign in…</p>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <div className="auth-card-body">
        <h3 className="state-title">Create your organisation</h3>
        <p className="state-message">
          AxeBOM is invite-only beyond this step — once your organisation exists, you invite the
          rest of your team as its Owner.
        </p>
      </div>

      <form onSubmit={(e) => void onSubmit(e)}>
        <label className="field">
          <span>Organisation name</span>
          <input type="text" required autoComplete="organization" {...field('organisationName')} />
        </label>

        <div className="field-pair">
          <label className="field">
            <span>First name</span>
            <input type="text" required autoComplete="given-name" {...field('givenName')} />
          </label>
          <label className="field">
            <span>Last name</span>
            <input type="text" required autoComplete="family-name" {...field('familyName')} />
          </label>
        </div>

        <label className="field">
          <span>Email</span>
          <input type="email" required autoComplete="email" {...field('email')} />
        </label>

        <label className="field">
          <span>Password</span>
          <input type="password" required autoComplete="new-password" {...field('password')} />
          <small>Upper case, lower case, a digit and a symbol.</small>
        </label>

        {error && <p className="field-error">{error}</p>}

        <div className="state-actions">
          <button className="btn btn-primary" type="submit" disabled={submitting}>
            {submitting ? 'Creating…' : 'Create organisation'}
          </button>
        </div>
      </form>

      <p className="auth-card-foot">
        Already have an account? <Link to="/projects">Sign in</Link>
      </p>
    </AuthShell>
  );
}
