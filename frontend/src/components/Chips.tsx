/**
 * The two chips that appear on nearly every screen.
 *
 * ⚠ NEITHER CAN BE RENDERED WITHOUT ITS LABEL.
 *
 * There is no `showLabel={false}` and no icon-only variant, deliberately. The
 * moment one exists somebody uses it in a dense table — which is exactly where
 * a colour-blind reader most needs the word — and the accessibility failure
 * ships inside a compliance report.
 *
 * docs/07-FRONTEND-SPEC.md §2.
 */

import { bomMeta, severityMeta } from '../design/theme';

interface BomTypeChipProps {
  type: string;
  /** Renders the honest one-line description as a tooltip. */
  describe?: boolean;
}

/** BomTypeChip renders glyph + label + accent. */
export function BomTypeChip({ type, describe = false }: BomTypeChipProps) {
  const meta = bomMeta(type);
  return (
    <span className="chip" data-bom={meta.token} title={describe ? meta.summary : undefined}>
      {/*
       * aria-hidden on the glyph: it is decoration reinforcing the label a
       * screen reader already reads. Announcing "black square SBOM" is noise.
       */}
      <span aria-hidden="true">{meta.glyph}</span>
      <span>{meta.label}</span>
    </span>
  );
}

interface SeverityBadgeProps {
  severity: string | null | undefined;
  /**
   * count renders "High · 12" for a summary cell. The severity word is still
   * present, so the count never becomes the only content.
   */
  count?: number;
}

/** SeverityBadge renders glyph + word + accent. */
export function SeverityBadge({ severity, count }: SeverityBadgeProps) {
  const meta = severityMeta(severity);
  return (
    <span className="sev" data-sev={meta.token}>
      <span aria-hidden="true">{meta.glyph}</span>
      <span>{meta.label}</span>
      {count !== undefined && <span className="sev-count">{count}</span>}
    </span>
  );
}

/**
 * StatusPill renders an engine or scan status.
 *
 * ⚠ `partial` AND `unavailable` ARE FIRST-CLASS, NOT ERRORS. One engine
 * covering eleven of twelve ecosystems is useful output plus a known gap, and
 * both halves have to reach the reader. Rendering them as failures teaches a
 * user to ignore the one status that means "look here".
 */
export function StatusPill({ status }: { status: string }) {
  return (
    <span className="pill" data-status={statusTone(status)}>
      {statusLabel(status)}
    </span>
  );
}

function statusTone(status: string): 'ok' | 'warn' | 'down' | 'info' {
  switch (status) {
    case 'succeeded':
    case 'ready':
    case 'completed':
      return 'ok';
    case 'partial':
    case 'unavailable':
    case 'no-engine':
    case 'completed_with_errors':
    case 'skipped':
      return 'warn';
    case 'failed':
    case 'timeout':
    case 'revoked':
    case 'expired':
      return 'down';
    default:
      return 'info';
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'completed_with_errors':
      return 'completed with errors';
    case 'no-engine':
      return 'no engine';
    default:
      return status.replace(/_/g, ' ');
  }
}

/**
 * ProvenanceChips names which engines saw a thing.
 *
 * ⚠ THE LIST, NOT A COUNT. "Detected by 3 engines" hides which three, and the
 * question a reviewer actually asks is "did the one I trust see it" — three
 * engines agreeing is a different fact from three engines that all read the
 * same lockfile.
 */
export function ProvenanceChips({ engines }: { engines: readonly string[] }) {
  if (engines.length === 0) {
    return <span className="not-provided">not-provided</span>;
  }
  return (
    <span className="provenance">
      {engines.map((e) => (
        <span key={e} className="provenance-chip">
          {e}
        </span>
      ))}
    </span>
  );
}

/**
 * NotProvided renders an absent value EXPLICITLY.
 *
 * ⚠ NEVER A BLANK CELL. Blank reads as "this table has no such column" or "we
 * did not look"; `not-provided` says we looked and there was nothing. Both
 * score zero for completeness, but only one of them is a statement the reader
 * can act on (CLAUDE.md invariant 3).
 */
export function NotProvided() {
  return (
    <span className="not-provided" title="Recorded as not-provided. Scores zero for completeness.">
      not-provided
    </span>
  );
}

/** Value renders a string, or NotProvided when it is empty. */
export function Value({ children }: { children: string | null | undefined }) {
  const text = (children ?? '').trim();
  if (text === '' || text === 'not-provided') return <NotProvided />;
  return <>{text}</>;
}
