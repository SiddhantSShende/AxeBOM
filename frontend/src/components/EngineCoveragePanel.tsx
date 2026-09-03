/**
 * EngineCoveragePanel — which OSINT engines feed one BOM type, and whether
 * each has ever actually run for this project.
 *
 * ⚠ "NEVER RUN" IS ITS OWN STATE, NOT A BLANK CELL. CLAUDE.md invariant 12:
 * every report states what it could not see, and that discipline belongs in
 * navigation too — a customer deciding whether to trust a CBOM should not
 * have to already know cbomkit-theia exists to wonder whether it ran.
 *
 * Reused by a BOM type's home page (scoped to one project, one family) and by
 * the engine tool-management screen (no project — registry facts only).
 */

import { StatusPill } from './Chips';
import { ErrorState, SkeletonRows } from './States';
import { useEngines, type EngineInfo } from '../lib/engines';
import { bomMeta, type BomType } from '../design/theme';

interface EngineCoveragePanelProps {
  family: BomType;
  /** Omit to show registry facts only, with no per-project run history. */
  projectId?: string;
}

export function EngineCoveragePanel({ family, projectId }: EngineCoveragePanelProps) {
  const { engines, isPending, isError, error } = useEngines(projectId, family);

  if (isPending) return <SkeletonRows rows={3} columns={4} />;
  if (isError) return <ErrorState error={error} action="load engine coverage" />;

  const rows = engines ?? [];
  const meta = bomMeta(family);

  return (
    <section aria-labelledby={`engine-coverage-${meta.token}`} className="card">
      <h3 id={`engine-coverage-${meta.token}`}>Engine coverage</h3>
      {/*
        ⚠ THE BOM-TYPE SUMMARY IS NOT REPEATED HERE. Every screen that mounts
        this panel already prints `meta.summary` as its page tagline, so the
        same two-line paragraph appeared twice within one viewport. What this
        panel owes the reader is what the TABLE means, which the caption below
        says.
      */}

      <div className="table-wrap">
        <table className="table">
          <caption className="table-caption">
            {projectId
              ? "Every engine registered for this BOM type, and this project's most recent run of it."
              : 'Every engine registered for this BOM type.'}
          </caption>
          <thead>
            <tr>
              <th scope="col">Engine</th>
              <th scope="col">Runs as</th>
              <th scope="col">Produces</th>
              {projectId && <th scope="col">Last run</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <EngineRow key={e.engine_id} engine={e} showLastRun={Boolean(projectId)} />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function EngineRow({ engine, showLastRun }: { engine: EngineInfo; showLastRun: boolean }) {
  return (
    <tr>
      <td>
        {engine.engine_id}
        {engine.requires_import && <span className="chip-note">import only</span>}
        {engine.is_derived && <span className="chip-note">derived</span>}
      </td>
      <td>{modeLabel(engine.mode)}</td>
      <td>{engine.produces.join(', ')}</td>
      {showLastRun && (
        <td>
          {engine.last_run ? (
            <StatusPill status={engine.last_run.status} />
          ) : (
            <span
              className="not-provided"
              title="No scan has invoked this engine for this project yet."
            >
              never run
            </span>
          )}
        </td>
      )}
    </tr>
  );
}

function modeLabel(mode: string): string {
  switch (mode) {
    case 'container':
      return 'sandboxed container';
    case 'pip':
      return 'unsandboxed (pip)';
    case 'internal':
      return 'AxeBOM-native, not a scanner';
    default:
      return mode || 'unknown';
  }
}
