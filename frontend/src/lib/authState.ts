/**
 * The session's shape and its React context.
 *
 * A module of its own because a file that exports both a component and a
 * context breaks Fast Refresh: the provider remounts on every edit and drops
 * the session mid-development. The provider lives in AuthContext.tsx and the
 * hook in useAuth.ts.
 */

import { createContext } from 'react';
import type { User } from 'oidc-client-ts';
import type { Membership } from './auth';

export interface AuthState {
  /** null while the initial session probe is in flight. */
  loading: boolean;
  user: User | null;
  name: string;
  memberships: Membership[];
  /** The organisation whose data the app is showing. */
  activeOrg: Membership | null;
  /** Set when a sign-in attempt failed, so the UI can say why. */
  error: string | null;
  signIn: () => void;
  signOut: () => void;
  selectOrg: (orgId: string) => void;
}

export const AuthCtx = createContext<AuthState | null>(null);
