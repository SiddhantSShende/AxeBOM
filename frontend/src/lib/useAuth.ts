/**
 * The hook every screen uses to reach the session.
 *
 * Split out because a file exporting both a component and a hook breaks Fast
 * Refresh — the provider would remount on every edit and drop the session.
 */

import { useContext } from 'react';
import { AuthCtx, type AuthState } from './authState';

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error('useAuth used outside AuthProvider');
  return ctx;
}
