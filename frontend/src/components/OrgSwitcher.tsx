/**
 * Which organisation the app is acting in.
 *
 * ⚠ A CONSULTANT HOLDS A ROLE IN SEVERAL TENANTS, WITH DIFFERENT RIGHTS IN EACH.
 *
 * The seed's carol is analyst in Acme and viewer in Beta, and the access token
 * carries both grants at once. Without a visible switcher the app silently
 * picks one — and the user cannot tell which tenant's data they are reading,
 * which in a multi-tenant compliance product is the worst kind of ambiguity.
 *
 * Renders nothing for the single-tenant case: a control with one option is
 * furniture, and it would appear on every screen for the majority of users.
 */

import { useAuth } from '../lib/useAuth';

export function OrgSwitcher() {
  const { memberships, activeOrg, selectOrg } = useAuth();
  if (memberships.length < 2 || !activeOrg) return null;

  return (
    <label className="org-switcher">
      <span className="sr-only">Organisation</span>
      <select
        value={activeOrg.orgId}
        onChange={(e) => selectOrg(e.target.value)}
        aria-label="Organisation"
      >
        {memberships.map((m) => (
          <option key={m.orgId} value={m.orgId}>
            {m.orgDomain} · {m.role}
          </option>
        ))}
      </select>
    </label>
  );
}
