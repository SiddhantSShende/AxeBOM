/**
 * The hook every screen uses to reach the session.
 *
 * Split out because a file exporting both a component and a hook breaks Fast
 * Refresh — the provider would remount on every edit and drop the session.
 */

import { useContext } from 'react';
import { AuthCtx, type AuthState } from './authState';
import { roleAtLeast, type Role } from './auth';

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error('useAuth used outside AuthProvider');
  return ctx;
}

/**
 * useRole is the first consumer of `activeOrg.role` for UI gating — every
 * screen before this one only READ the role (OrgSwitcher, SessionMenu), never
 * decided visibility from it. `atLeast` mirrors the server's own
 * `authz.RoleAtLeast`, and carries the same warning: it hides a control the
 * server would refuse anyway, it does not replace the refusal.
 */
export function useRole(): { role: Role | null; atLeast: (want: Role) => boolean } {
  const { activeOrg } = useAuth();
  const role = activeOrg?.role ?? null;
  return { role, atLeast: (want) => roleAtLeast(role, want) };
}
