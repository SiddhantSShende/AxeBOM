/**
 * The report viewer.
 *
 * ⚠ TWO THINGS ARE PROMINENT AND NOT FOOTER MATERIAL:
 *
 *   Coverage, BOTH numbers, side by side. Publishing only the declaration
 *   number and calling it "coverage" is how tools ship misleading 100% scores —
 *   a BOM full of explicit `not-provided` declares everything and substantiates
 *   nothing.
 *
 *   Engine Coverage, including ecosystems detected with NO available engine.
 *   This is the honest denominator. An SBOM that silently omits an ecosystem
 *   converts an unknown into a false negative the customer trusts, so it
 *   belongs where a reader will actually see it.
 *
 * docs/07-FRONTEND-SPEC.md §6.
 */

import { useState } from 'react';
import { useParams } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { useReport, type Report } from '../../lib/reports';
import { BomTypeChip, StatusPill, Value } from '../../components/Chips';
import { CommentRail } from '../../components/CommentRail';
import { CopyableCode, ErrorState, SkeletonRows } from '../../components/States';
import { AnimatePresence } from 'motion/react';
import { ShareDialog } from './ShareDialog';

export function ReportViewer() {
  const { id = '' } = useParams();
  const [sharing, setSharing] = useState(false);
  const queryClient = useQueryClient();

  const query = useReport(id);

  if (query.isPending) return <SkeletonRows rows={10} columns={3} />;
  if (query.isError) {
    return (
      <ErrorState
        error={query.error}
        action="load this report"
        onRetry={() => void query.refetch()}
      />
    );
  }

  // ⚠ NORMALIZED HERE, ONCE, RATHER THAN GUARDED AT EVERY USE SITE. A queued
  // or rendering report genuinely has no coverage/engine data yet (see
  // lib/reports.ts's Report type) — that is an honest "not yet computed"
  // state, not a bug, and the `?? []` fallbacks below let every section
  // render that state instead of crashing on it.
  const report: Report = {
    ...query.data,
    coverage_fields: query.data.coverage_fields ?? [],
    engines: query.data.engines ?? [],
    ecosystems_with_no_engine: query.data.ecosystems_with_no_engine ?? [],
  };

  return (
    <div className="report">
      <header className="report-head">
        <div>
          <h1>{report.project_name}</h1>
          <p className="tagline">
            <BomTypeChip type={report.bom_type} /> {levelLabel(report.level)} · generated{' '}
            {report.generated_at}
          </p>
        </div>
        <div className="report-actions">
          <StatusPill status={report.status} />
          <DownloadMenu report={report} />
          <button
            type="button"
            className="btn"
            onClick={() => setSharing(true)}
            disabled={report.status !== 'ready'}
          >
            Share
          </button>
        </div>
      </header>

      {report.status === 'failed' && (
        <div className="state state-error" role="alert">
          <h3 className="state-title">This report did not render</h3>
          <p className="state-message">
            The renderer stopped with <code>{report.error_code}</code>.
          </p>
        </div>
      )}

      {report.truncated && (
        <div className="callout callout-warn">
          <h3>Truncated</h3>
          <p>{report.truncation_note}</p>
        </div>
      )}

      {report.level_note && (
        <div className="callout">
          <h3>What this level includes</h3>
          <p>{report.level_note}</p>
        </div>
      )}

      <CoveragePanel report={report} />
      <EngineCoverageTable report={report} />
      <Provenance report={report} />
      <CommentRail reportId={report.id} />

      <AnimatePresence>
        {sharing && (
          <ShareDialog
            reportId={report.id}
            visibility={report.visibility}
            onClose={() => {
              setSharing(false);
              void queryClient.invalidateQueries({ queryKey: ['shares', report.id] });
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

/**
 * CoveragePanel shows both numbers with the difference spelled out.
 *
 * ⚠ SIDE BY SIDE, EQUALLY SIZED. Making completeness the headline and
 * declaration a footnote would be honest but incomplete; making declaration
 * the headline would be the misleading-100% failure. Both, adjacent, with what
 * each counts written underneath.
 */
function CoveragePanel({ report }: { report: Report }) {
  const [showFields, setShowFields] = useState(false);

  // ⚠ NOT YET COMPUTED IS NOT ZERO. A `queued` or `rendering` report has no
  // completeness/declaration numbers yet — the API omits the field entirely
  // rather than sending 0 — and this renders that honestly instead of
  // claiming a measured 0.00% (same reasoning as
  // services/report/internal/store/bomsource.go's loadDocumentMeta).
  const pct = (v: number | undefined) => (typeof v === 'number' ? `${v.toFixed(2)}%` : 'not yet computed');

  return (
    <section className="coverage" aria-labelledby="coverage-h">
      <h2 id="coverage-h">Coverage</h2>

      <div className="coverage-numbers">
        <div className="coverage-number">
          <span className="coverage-value">{pct(report.completeness_pct)}</span>
          <span className="coverage-label">Completeness</span>
          <p className="coverage-note">
            Substantive values only. <strong>This is the compliance signal.</strong>
          </p>
        </div>
        <div className="coverage-number">
          <span className="coverage-value">{pct(report.declaration_pct)}</span>
          <span className="coverage-label">Declaration</span>
          <p className="coverage-note">
            Any value, including an explicit <code>not-provided</code>. A representation check —{' '}
            <strong>not</strong> a compliance number.
          </p>
        </div>
      </div>

      {report.coverage_formula && (
        <p className="coverage-formula">
          <code>{report.coverage_formula}</code>
        </p>
      )}

      {/*
        ⚠ WHOSE JUDGEMENT THE WEIGHTS ARE. CERT-In assigns none; AxeBOM does,
        so a single percentage can exist. A reader who assumes the weighting is
        the regulator's is treating our judgement as theirs.
      */}
      <p className="coverage-caveat">
        Field weights are AxeBOM's judgement, not CERT-In's. The guideline assigns no weights; the
        per-field breakdown below is the unweighted evidence.
      </p>

      <button
        type="button"
        className="btn btn-quiet"
        aria-expanded={showFields}
        onClick={() => setShowFields((v) => !v)}
      >
        {showFields ? 'Hide' : 'Show'} per-field breakdown ({(report.coverage_fields ?? []).length} fields)
      </button>

      {showFields && (
        <table className="table table-compact">
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">Weight</th>
              <th scope="col">Substantive</th>
              <th scope="col">Declared</th>
              <th scope="col">Source</th>
            </tr>
          </thead>
          <tbody>
            {(report.coverage_fields ?? []).map((f) => (
              <tr key={f.field_id}>
                <th scope="row">{f.name}</th>
                <td>{f.weight}</td>
                <td>
                  {f.present}/{f.total}
                </td>
                <td>
                  {f.declared}/{f.total}
                </td>
                <td>CERT-In v2.0 p.{f.source_page}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/**
 * EngineCoverageTable is mandatory and not collapsible.
 *
 * ⚠ IT IS NOT BEHIND A DISCLOSURE. Every other section on this page can be
 * folded away; this one cannot, because it is the section that says what the
 * numbers above could not see. A reader who never expands it would take a
 * partial scan for a complete one.
 */
function EngineCoverageTable({ report }: { report: Report }) {
  return (
    <section className="engine-coverage" aria-labelledby="engines-h">
      <h2 id="engines-h">Engine Coverage</h2>
      <p className="section-note">
        What this report could and could not see. An engine reported <code>unavailable</code> is a
        stated gap; an ecosystem with no engine at all means its components are absent because
        nothing scanned them, not because none exist.
      </p>

      <table className="table">
        <thead>
          <tr>
            <th scope="col">Engine</th>
            <th scope="col">Version</th>
            <th scope="col">Status</th>
            <th scope="col">Database</th>
            <th scope="col">Ecosystems</th>
            <th scope="col">Note</th>
          </tr>
        </thead>
        <tbody>
          {(report.engines ?? []).map((e) => (
            <tr key={e.engine_id}>
              <th scope="row">{e.engine_id}</th>
              <td>
                <Value>{e.version}</Value>
              </td>
              <td>
                <StatusPill status={e.status} />
              </td>
              <td>
                <Value>{e.database_version}</Value>
              </td>
              <td>{e.ecosystems.join(', ') || <span className="not-provided">none</span>}</td>
              <td>
                <Value>{e.diagnostic}</Value>
              </td>
            </tr>
          ))}

          {(report.ecosystems_with_no_engine ?? []).map((eco) => (
            <tr key={`no-engine-${eco}`} className="row-warn">
              <th scope="row">(none)</th>
              <td>
                <span className="not-provided">not-provided</span>
              </td>
              <td>
                <StatusPill status="no-engine" />
              </td>
              <td>
                <span className="not-provided">not-provided</span>
              </td>
              <td>{eco}</td>
              <td>Detected in this project; no engine we run can scan it.</td>
            </tr>
          ))}

          {(report.engines ?? []).length === 0 && (report.ecosystems_with_no_engine ?? []).length === 0 && (
            <tr className="row-warn">
              <td colSpan={6}>
                No engine ran for this report. Every number above describes nothing.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}

function Provenance({ report }: { report: Report }) {
  return (
    <section aria-labelledby="prov-h">
      <h2 id="prov-h">Integrity</h2>
      <dl className="state-detail">
        <dt>SHA-256</dt>
        <dd>{report.sha256 ? <CopyableCode value={report.sha256} /> : <Value>{''}</Value>}</dd>
        <dt>Signed by</dt>
        <dd>
          {report.signing_key_id ? (
            <code>{report.signing_key_id}</code>
          ) : (
            <span className="not-provided">
              unsigned — this build has no signing key configured
            </span>
          )}
        </dd>
      </dl>
      <p className="section-note">
        Verify a downloaded artifact with <code>axebom verify &lt;file&gt;</code> and the published
        public key. That proves the file is the one issued; it says nothing about whether the scan
        was complete — for that, read Engine Coverage.
      </p>
    </section>
  );
}

/**
 * DownloadMenu offers every generated format with its render state.
 *
 * ⚠ A FORMAT STILL RENDERING IS SHOWN, DISABLED, WITH ITS STATE. Hiding it
 * would have a user conclude the format was never requested and start a second
 * scan — rendering is async, and a Complete BOM genuinely takes a while.
 */
function DownloadMenu({ report }: { report: Report }) {
  const [open, setOpen] = useState(false);
  // report.siblings is populated by GET /v1/reports/{id} (Handler.Get calls
  // store.Siblings, a same-schema query for other formats of the same scan
  // + bom_type) but never by the list endpoint or a just-created report, so
  // `?? []` is the ordinary case for a report that is the only format
  // rendered, not a guard against missing backend support.
  const all = [
    { id: report.id, format: report.format, status: report.status },
    ...(report.siblings ?? []),
  ];

  return (
    <div className="menu">
      <button type="button" className="btn" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        Download ▾
      </button>
      {open && (
        <ul className="menu-list">
          {all.map((s) => (
            <li key={s.id}>
              {s.status === 'ready' ? (
                <a
                  className="menu-item"
                  href={`/api/v1/reports/${s.id}/download`}
                  // Prefetching a large PDF on hover would download it twice.
                  // The metadata is already loaded; the bytes are the download.
                  download
                >
                  {s.format.toUpperCase()}
                </a>
              ) : (
                <span className="menu-item menu-item-disabled">
                  {s.format.toUpperCase()} <StatusPill status={s.status} />
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function levelLabel(level: string): string {
  return level === 'top_level' ? 'Top-Level' : level === 'complete' ? 'Complete' : level;
}
