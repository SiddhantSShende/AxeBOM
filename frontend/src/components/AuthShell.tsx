/**
 * The full-viewport frame for every pre-authentication screen.
 *
 * ⚠ NO SIDEBAR, NO TOP BAR — DELIBERATELY. SignIn and NoAccess used to render
 * inside the app <Shell>, so a signed-out visitor saw an empty navigation
 * rail around the card they were trying to get past. A visitor with no
 * session yet has nothing that rail can navigate to, so App.tsx now mounts
 * every screen that uses this shell OUTSIDE <Shell>, the same way
 * /auth/callback already had to be — one glass card over the ambient wash,
 * the way a hosted identity provider's own landing page reads.
 *
 * See the "Auth shell" block in design/app.css for the glass tier this uses
 * and why it differs from `.card` / `.state`.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Ambient } from './Ambient';
import { BrandMark } from './Icons';

export function AuthShell({
  children,
  className = '',
}: {
  children: ReactNode;
  /** Appended to the card, e.g. "auth-card-error" for the red accent border. */
  className?: string;
}) {
  return (
    <>
      <Ambient />
      <div className="auth-shell">
        <Link to="/" className="auth-mark">
          <BrandMark size={26} />
          <span>AxeBOM</span>
        </Link>
        <div className={className ? `auth-card ${className}` : 'auth-card'}>{children}</div>
      </div>
    </>
  );
}
