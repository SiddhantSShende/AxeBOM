/**
 * The top bar: who you are, which org, which theme, and the way out.
 *
 * Deliberately thin. Destinations live in the sidebar; this row holds only
 * controls that apply to every destination.
 *
 * ⚠ SIGN OUT IS A DIRECTLY VISIBLE BUTTON, NOT A DROPDOWN ITEM. Hiding it
 * behind an avatar menu would be tidier and would break `e2e/auth.spec.ts`,
 * which asserts `getByRole('button', { name: 'Sign out' })` — and more to the
 * point, "how do I get out of this" should never need a discovery step in a
 * tool people are audited on.
 */

import { OrgSwitcher } from './OrgSwitcher';
import { ThemeToggle } from './ThemeToggle';
import { IconMenu } from './Icons';
import { useShell } from '../design/shell';
import { useAuth } from '../lib/useAuth';

export function TopBar() {
  const setNavOpen = useShell((s) => s.setNavOpen);
  const navOpen = useShell((s) => s.navOpen);

  return (
    <header className="topbar">
      <button
        type="button"
        className="btn btn-quiet nav-toggle"
        onClick={() => setNavOpen(!navOpen)}
        aria-label="Open navigation"
        aria-expanded={navOpen}
      >
        <IconMenu />
      </button>

      <div className="topbar-actions">
        <OrgSwitcher />
        <ThemeToggle />
        <SessionMenu />
      </div>
    </header>
  );
}

/**
 * SessionMenu shows who is signed in and offers the way out.
 *
 * Renders nothing when signed out — a "Sign out" control on the sign-in screen
 * is noise, and the screen itself already says the state.
 */
function SessionMenu() {
  const { user, name, activeOrg, signOut } = useAuth();
  if (!user) return null;

  return (
    <div className="session">
      {/* Decorative: the name sits beside it and the title carries the role,
          so the initials are never the only place identity exists. */}
      <span className="avatar" aria-hidden="true">
        {initials(name)}
      </span>
      <span className="session-name" title={activeOrg ? `${name} — ${activeOrg.role}` : name}>
        {name}
      </span>
      <button className="btn btn-quiet" onClick={signOut}>
        Sign out
      </button>
    </div>
  );
}

/**
 * initials reduces a display name to at most two letters.
 *
 * Falls back to the first character of whatever it was given — an email with
 * no space, a single word — rather than rendering an empty circle, which
 * would read as a failed avatar image.
 */
function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return (parts[0]![0]! + parts[parts.length - 1]![0]!).toUpperCase();
}
