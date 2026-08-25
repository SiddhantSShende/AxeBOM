/**
 * Settings.
 *
 * ⚠ THE ORGANISATION PANEL IS READ-ONLY, AND IT SAYS WHY.
 *
 * There is no `/v1/orgs` route on any service, and no endpoint that lists
 * members or edits a role — identity moved to ZITADEL, which owns users,
 * organisations and role assignment. Drawing an editable-looking org form over
 * an API that does not exist would be a worse outcome than pointing at the
 * console that does own it.
 *
 * What is shown comes from the ID token's memberships, which the app already
 * has; this page adds no new API call.
 */

import { Link } from 'react-router';
import { ThemeToggle } from '../../components/ThemeToggle';
import { useAuth } from '../../lib/useAuth';

export function SettingsIndex() {
  const { name, user, memberships, activeOrg } = useAuth();

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Settings</h1>
          <p className="tagline">Your account, your organisations, and how AxeBOM notifies you</p>
        </div>
      </header>

      <section className="panel" aria-labelledby="account-heading">
        <h2 id="account-heading">Account</h2>
        <dl className="meta">
          <dt>Name</dt>
          <dd>{name}</dd>
          <dt>Signed in as</dt>
          <dd>{user?.profile.email ?? <span className="not-provided">not-provided</span>}</dd>
        </dl>
      </section>

      <section className="panel" aria-labelledby="orgs-heading">
        <h2 id="orgs-heading">Organisations</h2>
        {memberships.length === 0 ? (
          <p className="not-provided">not-provided</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Organisation</th>
                  <th scope="col">Your role</th>
                  <th scope="col">Active</th>
                </tr>
              </thead>
              <tbody>
                {memberships.map((m) => (
                  <tr key={m.orgId}>
                    <th scope="row">{m.orgDomain}</th>
                    <td>{m.role}</td>
                    <td>
                      {m.orgId === activeOrg?.orgId ? (
                        <span className="pill" data-status="ok">
                          active
                        </span>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="field-hint">
          Members, roles and invitations are managed in the identity console, not here. Your role
          above is read from the token this session was issued.
        </p>
        {/*
          A plain anchor, not a <Link>: /ui/console is proxied to ZITADEL by
          nginx in production and by vite.config.ts in development. It is not
          an SPA route, and routing it through the router would 404.
        */}
        <a className="btn" href="/ui/console" target="_blank" rel="noreferrer">
          Open identity console
        </a>
      </section>

      <section className="panel" aria-labelledby="appearance-heading">
        <h2 id="appearance-heading">Appearance</h2>
        <p className="field-hint">
          Light is the default. <strong>System</strong> keeps following your operating system rather
          than reading it once, so the app changes with it at dusk.
        </p>
        <ThemeToggle />
      </section>

      <section className="panel" aria-labelledby="notifications-heading">
        <h2 id="notifications-heading">Notifications</h2>
        <p className="field-hint">
          Where scan and report events are delivered — email addresses and webhook endpoints, with
          their recent delivery attempts.
        </p>
        <Link className="btn" to="/settings/notifications">
          Manage notifications
        </Link>
      </section>

      <section className="panel" aria-labelledby="engines-heading">
        <h2 id="engines-heading">Engines</h2>
        <p className="field-hint">
          Which OSINT engines run for each BOM type. Viewable by anyone; changing it needs the
          Admin role.
        </p>
        <Link className="btn" to="/settings/engines">
          Manage engines
        </Link>
      </section>
    </div>
  );
}
