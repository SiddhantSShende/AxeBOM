/**
 * The primary navigation.
 *
 * ⚠ THREE GROUPS IN ONE `<nav>`, NOT FIVE SEPARATE PRODUCTS. Projects sits on
 * top; the five BOM types are a labelled middle group, each a lens on that
 * same project data (see routes/boms/BomTypeHome.tsx); Generate/Scheduled/
 * Reports/Settings stay cross-cutting at the bottom. This mirrors the
 * "navigational reorg, not a data-model split" decision — the underlying
 * `project.project_classifications` table and single `bom_type`
 * discriminator (docs/01-DATA-MODEL.md) are unchanged.
 *
 * ⚠ COLLAPSING HIDES THE LABEL VISUALLY, NEVER FROM THE ACCESSIBLE NAME.
 *
 * The label stays in the DOM in an `.sr-only` span and is repeated in `title`,
 * so a collapsed sidebar and a screen reader announce the same destinations.
 * An icon-only nav whose names exist nowhere is the same failure as an
 * icon-only severity chip — the product already refuses that in
 * components/Chips.tsx, and the rule does not stop at the content area.
 *
 * On narrow screens this becomes a modal off-canvas panel. It is the same
 * markup either way; only the CSS and the focus handling differ.
 */

import { useEffect, useRef } from 'react';
import { Link, NavLink } from 'react-router';
import { useShell } from '../design/shell';
import { BOM_TYPES } from '../design/theme';
import {
  BrandMark,
  IconClose,
  IconCollapse,
  IconGenerate,
  IconProjects,
  IconReports,
  IconScheduled,
  IconSettings,
} from './Icons';

const NAV_TOP = [{ to: '/projects', label: 'Projects', Icon: IconProjects }] as const;

/**
 * BOM_NAV is a lens on the same projects, not five destinations. Each item
 * routes to that BOM type's home (routes/boms/BomTypeHome.tsx) — projects
 * classified for it, engine coverage, and whatever dedicated view already
 * exists. `data-bom` is what lets app.css give each item its own accent when
 * active, matching BomTypeChip elsewhere.
 */
const BOM_NAV = BOM_TYPES.map((b) => ({
  to: `/${b.type.toLowerCase()}`,
  label: b.label,
  glyph: b.glyph,
  token: b.token,
}));

const NAV_BOTTOM = [
  { to: '/generate', label: 'Generate', Icon: IconGenerate },
  { to: '/campaigns', label: 'Scheduled', Icon: IconScheduled },
  { to: '/reports', label: 'Reports', Icon: IconReports },
  { to: '/settings', label: 'Settings', Icon: IconSettings },
] as const;

export function Sidebar() {
  const collapsed = useShell((s) => s.collapsed);
  const toggleCollapsed = useShell((s) => s.toggleCollapsed);
  const navOpen = useShell((s) => s.navOpen);
  const setNavOpen = useShell((s) => s.setNavOpen);
  const panelRef = useRef<HTMLElement>(null);

  // ⚠ ESCAPE CLOSES THE MOBILE PANEL, AND ONLY THE MOBILE PANEL. On a wide
  // screen the sidebar is ordinary page furniture, not a dialog, and stealing
  // Escape there would break it for the drawer and the wizard underneath.
  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setNavOpen(false);
    };
    document.addEventListener('keydown', onKey);
    panelRef.current?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [navOpen, setNavOpen]);

  return (
    <>
      {/* The scrim exists only in the mobile layout; CSS hides it above 60rem. */}
      <div
        className="nav-scrim"
        data-open={navOpen ? 'true' : 'false'}
        onClick={() => setNavOpen(false)}
        aria-hidden="true"
      />

      <aside className="sidebar" ref={panelRef} tabIndex={-1}>
        <div className="sidebar-brand">
          <Link to="/projects" className="brand" onClick={() => setNavOpen(false)}>
            <BrandMark />
            <span className="brand-word">AxeBOM</span>
          </Link>
          <button
            type="button"
            className="btn btn-quiet nav-close"
            onClick={() => setNavOpen(false)}
            aria-label="Close navigation"
          >
            <IconClose />
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="Primary">
          <ul>
            {NAV_TOP.map(({ to, label, Icon }) => (
              <li key={to}>
                <NavLink to={to} title={label} onClick={() => setNavOpen(false)}>
                  <span className="nav-icon">
                    <Icon />
                  </span>
                  {/*
                    ⚠ ALWAYS RENDERED. `.sidebar-nav .nav-label` is clipped by
                    CSS when collapsed, not removed — an accessible name that
                    disappears with a layout preference is not an accessible
                    name.
                  */}
                  <span className="nav-label">{label}</span>
                </NavLink>
              </li>
            ))}
          </ul>

          {/*
            ⚠ A HEADING, NOT A SECOND `aria-label`. Two `<nav>` landmarks
            named "Primary" and "BOM types" would force a screen-reader user
            to guess which one holds Projects; one landmark with an internal
            heading keeps a single, ordered nav region while still giving the
            five BOM-type items a name of their own.
          */}
          <h3 className="sr-only" id="bom-nav-heading">
            BOM types
          </h3>
          <ul aria-labelledby="bom-nav-heading">
            {BOM_NAV.map(({ to, label, glyph, token }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  title={label}
                  data-bom={token}
                  onClick={() => setNavOpen(false)}
                >
                  <span className="nav-icon" aria-hidden="true">
                    {glyph}
                  </span>
                  <span className="nav-label">{label}</span>
                </NavLink>
              </li>
            ))}
          </ul>

          <ul>
            {NAV_BOTTOM.map(({ to, label, Icon }) => (
              <li key={to}>
                <NavLink to={to} title={label} onClick={() => setNavOpen(false)}>
                  <span className="nav-icon">
                    <Icon />
                  </span>
                  <span className="nav-label">{label}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <button
          type="button"
          className="btn btn-quiet sidebar-collapse"
          onClick={toggleCollapsed}
          aria-expanded={!collapsed}
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
        >
          <IconCollapse />
          <span className="nav-label">Collapse</span>
        </button>
      </aside>
    </>
  );
}
