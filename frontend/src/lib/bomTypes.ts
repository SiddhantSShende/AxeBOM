/**
 * The five BOM types.
 *
 * Each carries a glyph AND a label AND a colour token. Colour alone is never
 * the signal (WCAG 1.4.1) — these appear together constantly in project cards,
 * scan configs and filter chips, and a colour-blind user reading a
 * vulnerability report is a compliance risk, not an edge case.
 *
 * The `note` fields are deliberately honest. docs/00-MASTER-PLAN.md §2:
 * no open-source tool discovers physical hardware or quantum devices, and the
 * UI must not imply otherwise.
 */

export interface BomType {
  id: 'SBOM' | 'CBOM' | 'QBOM' | 'AIBOM' | 'HBOM';
  label: string;
  glyph: string;
  note: string;
  phase: number;
}

export const BOM_TYPES: readonly BomType[] = [
  {
    id: 'SBOM',
    label: 'Software',
    glyph: '▣',
    note: 'six engines, merged',
    phase: 8,
  },
  {
    id: 'CBOM',
    label: 'Cryptographic',
    glyph: '⚿',
    note: 'discovery',
    phase: 11,
  },
  {
    id: 'QBOM',
    label: 'Quantum',
    glyph: '◈',
    note: 'derived + device metadata',
    phase: 11,
  },
  {
    id: 'AIBOM',
    label: 'Artificial Intelligence',
    glyph: '◐',
    note: 'code scan + model enrichment',
    phase: 12,
  },
  {
    id: 'HBOM',
    label: 'Hardware',
    glyph: '▤',
    note: 'import, not discovery',
    phase: 15,
  },
] as const;
