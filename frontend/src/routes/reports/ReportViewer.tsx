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
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { BomTypeChip, StatusPill, Value } from '../../components/Chips';
import { CopyableCode, ErrorState, SkeletonRows } from '../../components/States';
import { ShareDialog } from './ShareDialog';

interface FieldCoverage {
  fieldId: string;
  name: string;
  present: number;
  declared: number;
  total: number;
  weight: number;
  sourcePage: number;
}

interface EngineCoverage {
  engineId: string;
  version: string;
  status: string;
  databaseVersion: string;
  ecosystems: string[];
  diagnostic: string;
}

export interface Report {
  id: string;
  projectName: string;
  bomType: string;
  level: string;
  levelNote: string;
  format: string;
  visibility: 'public' | 'private';
  status: 'queued' | 'rendering' | 'ready' | 'failed';
  sha256: string;
  sizeBytes: number;
  signingKeyId: string;
  truncated: boolean;
  truncationNote: string;
  errorCode: string;
  generatedAt: string;

  completenessPct: number;
  declarationPct: number;
  coverageFormula: string;
  coverageFields: FieldCoverage[];

  engines: EngineCoverage[];
  ecosystemsWithNoEngine: string[];

  siblings: { id: string; format: string; status: string }[];
}

export function ReportViewer() {
  const { id = '' } = useParams();
  const [sharing, setSharing] = useState(false);
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['report', id],
    queryFn: () => api.get<Report>(`/v1/reports/${id}`),
    // ⚠ POLL WHILE RENDERING, THEN STOP FOREVER. A finished report is
    // immutable, so refetching one costs a request and can never change an
    // answer; an unfinished one has to be watched or the page lies.
    refetchInterval: (q) =>
      q.state.data?.status === 'ready' || q.state.data?.status === 'failed' ? false : 3000,
    staleTime: 0,
  });

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

  const report = query.data;

  return (
    <div className="report">
      <header className="report-head">
        <div>
          <h1>{report.projectName}</h1>
          <p className="tagline">
            <BomTypeChip type={report.bomType} /> {levelLabel(report.level)} · generated{' '}
            {report.generatedAt}
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
            The renderer stopped with <code>{report.errorCode}</code>.
          </p>
        </div>
      )}

      {report.truncated && (
        <div className="callout callout-warn">
          <h3>Truncated</h3>
          <p>{report.truncationNote}</p>
        </div>
      )}

      {report.levelNote && (
        <div className="callout">
          <h3>What this level includes</h3>
          <p>{report.levelNote}</p>
        </div>
      )}

      <CoveragePanel report={report} />
      <EngineCoverageTable report={report} />
      <Provenance report={report} />

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

  return (
    <section className="coverage" aria-labelledby="coverage-h">
      <h2 id="coverage-h">Coverage</h2>

      <div className="coverage-numbers">
        <div className="coverage-number">
          <span className="coverage-value">{report.completenessPct.toFixed(2)}%</span>
          <span className="coverage-label">Completeness</span>
          <p className="coverage-note">
            Substantive values only. <strong>This is the compliance signal.</strong>
          </p>
        </div>
        <div className="coverage-number">
          <span className="coverage-value">{report.declarationPct.toFixed(2)}%</span>
          <span className="coverage-label">Declaration</span>
          <p className="coverage-note">
            Any value, including an explicit <code>not-provided</code>. A representation check —{' '}
            <strong>not</strong> a compliance number.
          </p>
        </div>
      </div>

      {report.coverageFormula && (
        <p className="coverage-formula">
          <code>{report.coverageFormula}</code>
        </p>
      )}

      {/*
        ⚠ WHOSE JUDGEMENT THE WEIGHTS ARE. CERT-In assigns none; EncoreBOM does,
        so a single percentage can exist. A reader who assumes the weighting is
        the regulator's is treating our judgement as theirs.
      */}
      <p className="coverage-caveat">
        Field weights are EncoreBOM's judgement, not CERT-In's. The guideline assigns no weights;
        the per-field breakdown below is the unweighted evidence.
      </p>

      <button
        type="button"
        className="btn btn-quiet"
        aria-expanded={showFields}
        onClick={() => setShowFields((v) => !v)}
      >
        {showFields ? 'Hide' : 'Show'} per-field breakdown ({report.coverageFields.length} fields)
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
            {report.coverageFields.map((f) => (
              <tr key={f.fieldId}>
                <th scope="row">{f.name}</th>
                <td>{f.weight}</td>
                <td>
                  {f.present}/{f.total}
                </td>
                <td>
                  {f.declared}/{f.total}
                </td>
                <td>CERT-In v2.0 p.{f.sourcePage}</td>
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
          {report.engines.map((e) => (
            <tr key={e.engineId}>
              <th scope="row">{e.engineId}</th>
              <td>
                <Value>{e.version}</Value>
              </td>
              <td>
                <StatusPill status={e.status} />
              </td>
              <td>
                <Value>{e.databaseVersion}</Value>
              </td>
              <td>{e.ecosystems.join(', ') || <span className="not-provided">none</span>}</td>
              <td>
                <Value>{e.diagnostic}</Value>
              </td>
            </tr>
          ))}

          {report.ecosystemsWithNoEngine.map((eco) => (
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

          {report.engines.length === 0 && report.ecosystemsWithNoEngine.length === 0 && (
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
          {report.signingKeyId ? (
            <code>{report.signingKeyId}</code>
          ) : (
            <span className="not-provided">
              unsigned — this build has no signing key configured
            </span>
          )}
        </dd>
      </dl>
      <p className="section-note">
        Verify a downloaded artifact with <code>encorebom verify &lt;file&gt;</code> and the
        published public key. That proves the file is the one issued; it says nothing about whether
        the scan was complete — for that, read Engine Coverage.
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
  const all = [{ id: report.id, format: report.format, status: report.status }, ...report.siblings];

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
