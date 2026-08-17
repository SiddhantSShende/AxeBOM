/**
 * The visual vocabulary: BOM types, severities, and the theme toggle.
 *
 * ⚠ EVERY ENTRY CARRIES A GLYPH AND A LABEL ALONGSIDE ITS COLOUR.
 *
 * Five BOM types and five severities appear together constantly — in project
 * cards, filter chips, table cells, report headers. Distinguishing them by
 * colour alone fails WCAG 1.4.1, and for a vulnerability report that is not an
 * accessibility nicety: a colour-blind reader who cannot tell Critical from
 * Low is a compliance risk.
 *
 * The types below make it impossible to render one without the other two: the
 * chip components take a key and read all three.
 *
 * docs/07-FRONTEND-SPEC.md §2.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

// ---------------------------------------------------------------------------
// BOM types
// ---------------------------------------------------------------------------

export type BomType = 'SBOM' | 'CBOM' | 'QBOM' | 'AIBOM' | 'HBOM';

export interface BomTypeMeta {
  readonly type: BomType;
  /** Rendered before the label. Never the only signal. */
  readonly glyph: string;
  readonly label: string;
  /** CSS custom-property suffix: `--sbom`, `--sbom-bg`. */
  readonly token: string;
  /**
   * An honest one-line description of what this BOM type actually is.
   *
   * ⚠ TWO OF THESE ARE DELIBERATELY UNDERSOLD, and the UI must not oversell
   * them. There is no open-source HBOM scanner — HBOM is a structured import.
   * QBOM is largely a derivation from CBOM discovery. Implying discovery would
   * have a customer wait for results that are never coming.
   */
  readonly summary: string;
}

export const BOM_TYPES: readonly BomTypeMeta[] = [
  {
    type: 'SBOM',
    glyph: '▣',
    label: 'SBOM',
    token: 'sbom',
    summary: 'Software components, discovered by scanning your source.',
  },
  {
    type: 'CBOM',
    glyph: '⚿',
    label: 'CBOM',
    token: 'cbom',
    summary: 'Cryptographic assets, discovered by scanning your source.',
  },
  {
    type: 'QBOM',
    glyph: '◈',
    label: 'QBOM',
    token: 'qbom',
    summary:
      'Largely DERIVED from CBOM discovery with quantum-vulnerability rules ' +
      'applied. Only device metadata is captured separately — there is no ' +
      'quantum-hardware scanner.',
  },
  {
    type: 'AIBOM',
    glyph: '◐',
    label: 'AIBOM',
    token: 'aibom',
    summary: 'AI/ML models and datasets, discovered by scanning your source.',
  },
  {
    type: 'HBOM',
    glyph: '▤',
    label: 'HBOM',
    token: 'hbom',
    summary:
      'IMPORTED, not discovered. Hardware inventory comes from a CSV or a ' +
      'form you fill in; no scanner produces it.',
  },
] as const;

const BOM_BY_TYPE = new Map(BOM_TYPES.map((b) => [b.type, b]));

/**
 * bomMeta never returns undefined.
 *
 * An unknown BOM type is a bug, but rendering nothing where a chip belongs is a
 * worse one: the row silently loses a column and nobody notices. An explicit
 * unknown chip is visible and searchable.
 */
export function bomMeta(type: string): BomTypeMeta {
  return (
    BOM_BY_TYPE.get(type as BomType) ?? {
      type: type as BomType,
      glyph: '？',
      label: type || 'unknown',
      token: 'hbom',
      summary: 'This BOM type is not one this build knows about.',
    }
  );
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';

export interface SeverityMeta {
  readonly severity: Severity;
  readonly glyph: string;
  readonly label: string;
  readonly token: string;
  /** Sort weight, highest first. Used for ordering, never for arithmetic. */
  readonly rank: number;
}

export const SEVERITIES: readonly SeverityMeta[] = [
  { severity: 'critical', glyph: '⬤', label: 'Critical', token: 'sev-critical', rank: 5 },
  { severity: 'high', glyph: '◆', label: 'High', token: 'sev-high', rank: 4 },
  { severity: 'medium', glyph: '▲', label: 'Medium', token: 'sev-medium', rank: 3 },
  { severity: 'low', glyph: '■', label: 'Low', token: 'sev-low', rank: 2 },
  { severity: 'none', glyph: '○', label: 'None', token: 'sev-none', rank: 1 },
  /**
   * ⚠ `unknown` IS A REAL STATE AND MUST NOT COLLAPSE INTO `none`.
   *
   * "No severity was asserted" and "assessed as no severity" are different
   * claims, and rendering the first as the second understates risk in a
   * document a customer acts on.
   */
  { severity: 'unknown', glyph: '?', label: 'Unknown', token: 'sev-unknown', rank: 0 },
] as const;

const SEVERITY_BY_KEY = new Map(SEVERITIES.map((s) => [s.severity, s]));

export function severityMeta(severity: string | null | undefined): SeverityMeta {
  const key = (severity ?? '').toLowerCase() as Severity;
  return SEVERITY_BY_KEY.get(key) ?? SEVERITY_BY_KEY.get('unknown')!;
}

/** compareSeverity orders most severe first. */
export function compareSeverity(a: string, b: string): number {
  return severityMeta(b).rank - severityMeta(a).rank;
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

export type ThemeChoice = 'system' | 'light' | 'dark';

interface ThemeState {
  choice: ThemeChoice;
  setChoice: (choice: ThemeChoice) => void;
}

/**
 * The theme store.
 *
 * ⚠ ONE OF THE FEW THINGS ZUSTAND MAY HOLD. Server data lives in TanStack
 * Query and nowhere else; Zustand holds only state that never round-trips —
 * theme, sidebar, and the generate-wizard draft.
 *
 * `system` is the default and is NOT the same as reading the OS preference
 * once. It means "keep following the OS", so a user who changes their OS theme
 * at dusk sees the app follow without touching a setting.
 */
export const useTheme = create<ThemeState>()(
  persist(
    (set) => ({
      choice: 'system',
      setChoice: (choice) => {
        set({ choice });
        applyTheme(choice);
      },
    }),
    {
      name: 'encorebom.theme',
      onRehydrateStorage: () => (state) => {
        if (state) applyTheme(state.choice);
      },
    },
  ),
);

/**
 * applyTheme writes the choice to the document.
 *
 * `system` REMOVES the attribute rather than setting it to a resolved value.
 * Resolving it here would freeze the theme at whatever the OS said on load,
 * which is the bug that makes an app stop following the system at dusk.
 */
export function applyTheme(choice: ThemeChoice): void {
  const root = document.documentElement;
  if (choice === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', choice);
  }
}
