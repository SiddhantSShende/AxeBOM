/**
 * The icon set.
 *
 * ⚠ EVERY ICON IS `aria-hidden` AND NONE OF THEM CARRIES MEANING ALONE.
 *
 * This is the same rule the BOM and severity chips follow (components/Chips.tsx,
 * CLAUDE.md invariant on colour): an icon reinforces a label, it never replaces
 * one. Where a control is icon-only — the sidebar in its collapsed state, the
 * mobile nav toggle — the label is still in the accessible name via `aria-label`
 * or an `.sr-only` span, so a screen reader and a collapsed sidebar say exactly
 * the same thing.
 *
 * Inline SVG rather than an icon package: eight paths cost less than a
 * dependency, they inherit `currentColor` so they theme for free, and they stay
 * crisp where a Unicode glyph would render as whatever the user's font happens
 * to have.
 *
 * `stroke-width` is 1.5 at 16px — thinner reads as broken on a low-DPI display,
 * thicker reads as a toy.
 */

interface IconProps {
  /** Overrides the 16px default. The stroke stays optically consistent. */
  size?: number | undefined;
}

function Svg({ size = 16, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export function IconProjects(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M2 4.5 8 1.5l6 3-6 3-6-3Z" />
      <path d="M2 8l6 3 6-3" />
      <path d="M2 11.5 8 14.5l6-3" />
    </Svg>
  );
}

export function IconGenerate(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 1.5 9.6 6 14 7.5 9.6 9 8 13.5 6.4 9 2 7.5 6.4 6 8 1.5Z" />
    </Svg>
  );
}

export function IconScheduled(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="8" cy="8" r="6.25" />
      <path d="M8 4.5V8l2.5 1.5" />
    </Svg>
  );
}

export function IconReports(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M3 1.75h6L13 6v8.25H3V1.75Z" />
      <path d="M9 1.75V6h4" />
      <path d="M5.5 9.5h5M5.5 11.75h3" />
    </Svg>
  );
}

export function IconSettings(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M2 4.5h12M2 11.5h12" />
      <circle cx="6" cy="4.5" r="1.75" />
      <circle cx="10.5" cy="11.5" r="1.75" />
    </Svg>
  );
}

/** Points the way the sidebar will move, so it is rotated by CSS when collapsed. */
export function IconCollapse(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M9.5 3.5 5 8l4.5 4.5" />
    </Svg>
  );
}

export function IconMenu(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M2.25 4h11.5M2.25 8h11.5M2.25 12h11.5" />
    </Svg>
  );
}

export function IconClose(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M3.75 3.75l8.5 8.5M12.25 3.75l-8.5 8.5" />
    </Svg>
  );
}

/**
 * The brand mark: an axe, not a letter.
 *
 * ⚠ STRAIGHT EDGES, NOT A CURVED BLOB. A rounded wedge reads as a balloon or a
 * lollipop at 22px — the shape needs hard corners to be legible as a blade at
 * a glance, and legible in the collapsed sidebar's 16px is the harder
 * constraint than legible here.
 */
export function BrandMark({ size = 22 }: IconProps) {
  return (
    <svg
      className="brand-mark"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id="axebom-mark" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="var(--primary)" />
          <stop offset="100%" stopColor="var(--qbom)" />
        </linearGradient>
      </defs>
      <rect x="1" y="1" width="22" height="22" rx="6.5" fill="url(#axebom-mark)" />
      {/* Haft. */}
      <path
        d="M7.5 20 12.5 9.5"
        stroke="#fff"
        strokeOpacity="0.97"
        strokeWidth="2.6"
        strokeLinecap="round"
      />
      {/* Blade: a plain wedge — three straight edges, no curves — pointing up
          and away from the haft. */}
      <path
        d="M12 10.8 L15.5 3.5 L21 8 L14 12 Z"
        fill="#fff"
        fillOpacity="0.97"
        strokeLinejoin="round"
      />
    </svg>
  );
}
