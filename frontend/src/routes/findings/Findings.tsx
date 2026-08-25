/**
 * Findings, grouped by cluster.
 *
 * ⚠ ONE ROW PER CLUSTER, NOT PER ADVISORY IDENTIFIER.
 *
 * Grype emits GHSA, OSV-Scanner emits OSV, Dependency-Check emits CVE, Trivy
 * emits both. Listing each is the same vulnerability counted three times, and a
 * customer reading "48 criticals" when there are 16 will either panic or, worse,
 * learn to discount the number.
 *
 * docs/07-FRONTEND-SPEC.md §6.
 */

import { useState } from 'react';
import { useParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { ProvenanceChips, SeverityBadge, Value } from '../../components/Chips';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { compareSeverity } from '../../design/theme';
import { useGenerateCSAFAdvisory, useCSAFAdvisories } from '../../lib/csaf';
import {
  useCreateVEXStatement,
  useVEXHistory,
  VEX_JUSTIFICATIONS,
  VEX_SCOPES,
  VEX_STATUSES,
  type CreateVEXStatementInput,
  type VEXScope,
  type VEXStatus,
} from '../../lib/vex';

export interface SeveritySource {
  engine: string;
  severity: string;
  cvssVersion: string;
  cvssScore: string;
  cvssVector: string;
}

export interface Finding {
  clusterId: string;
  displayId: string;
  aliases: string[];
  severity: string;
  cvssVersion: string;
  cvssScore: string;
  /** ⚠ Never resolved into one number — see ConflictDetail. */
  severityConflict: boolean;
  severitySources: SeveritySource[];
  components: { key: string; name: string; version: string }[];
  fixedInMin: string;
  fixOrdering: 'known' | 'unknown';
  detectedBy: string[];
  vexStatus: string;
  vexJustification: string;
}

export function Findings() {
  const { id = '' } = useParams();

  const query = useQuery({
    queryKey: ['findings', id],
    queryFn: () => api.get<{ findings: Finding[] }>(`/v1/projects/${id}/findings`),
    staleTime: 30_000,
  });

  if (query.isPending) return <SkeletonRows rows={10} columns={6} />;
  if (query.isError) {
    return (
      <ErrorState
        error={query.error}
        action="load this project's findings"
        onRetry={() => void query.refetch()}
      />
    );
  }

  const findings = [...(query.data?.findings ?? [])].sort((a, b) =>
    compareSeverity(a.severity, b.severity),
  );

  if (findings.length === 0) {
    return (
      <EmptyState
        title="No findings"
        guidance={
          <>
            No vulnerabilities matched this project's components. Check the{' '}
            <strong>Engine Coverage</strong> section of a report before reading that as clean — an
            ecosystem with no available engine produces no findings for a different reason.
          </>
        }
      />
    );
  }

  return (
    <div className="findings">
      <p className="deps-count" role="status">
        <strong>{findings.length}</strong> findings, deduplicated across identifier schemes. One
        vulnerability reported by four engines is one row.
      </p>

      <table className="table">
        <thead>
          <tr>
            <th scope="col">Advisory</th>
            <th scope="col">Severity</th>
            <th scope="col">Components</th>
            <th scope="col">Fixed in</th>
            <th scope="col">Detected by</th>
            <th scope="col">VEX</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <FindingRow key={f.clusterId} finding={f} projectId={id} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingRow({ finding: f, projectId }: { finding: Finding; projectId: string }) {
  const [expanded, setExpanded] = useState(false);
  const [triaging, setTriaging] = useState(false);

  return (
    <>
      <tr>
        <th scope="row">
          <span className="advisory">{f.displayId}</span>
          {f.aliases.length > 0 && (
            <span className="aliases" title={f.aliases.join(', ')}>
              +{f.aliases.length} alias{f.aliases.length === 1 ? '' : 'es'}
            </span>
          )}
        </th>

        <td>
          <SeverityBadge severity={f.severity} />
          {f.cvssScore && (
            <span className="cvss">
              {f.cvssScore} (v{f.cvssVersion})
            </span>
          )}
          {/*
            ⚠ THE CONFLICT IS A BADGE, NOT A HIDDEN FIELD, AND IT EXPANDS.
            A reviewer WILL ask why Trivy said High and Grype said Critical, and
            the answer must be one click away. Averaging or max-ing the two
            would invent a number no source asserted — and v2, v3.1 and v4.0 are
            different scales, so the arithmetic is meaningless as well.
          */}
          {f.severityConflict && (
            <button
              type="button"
              className="conflict"
              aria-expanded={expanded}
              onClick={() => setExpanded((v) => !v)}
            >
              sources disagree {expanded ? '▴' : '▾'}
            </button>
          )}
        </td>

        <td>
          {f.components.map((c) => (
            <span key={c.key} className="affected">
              {c.name} <span className="text-faint">{c.version}</span>
            </span>
          ))}
        </td>

        <td>{fixCell(f)}</td>

        <td>
          <ProvenanceChips engines={f.detectedBy} />
        </td>

        <td>
          {f.vexStatus ? (
            <span className="vex" data-vex={f.vexStatus}>
              {f.vexStatus.replace(/_/g, ' ')}
            </span>
          ) : (
            <span className="text-faint">none</span>
          )}
          {' · '}
          <button type="button" className="btn" onClick={() => setTriaging((v) => !v)}>
            {triaging ? 'Close' : 'Triage'}
          </button>
        </td>
      </tr>

      {expanded && (
        <tr className="conflict-detail">
          <td colSpan={6}>
            <ConflictDetail sources={f.severitySources} />
          </td>
        </tr>
      )}

      {triaging && (
        <tr>
          <td colSpan={6}>
            <TriagePanel finding={f} projectId={projectId} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * TriagePanel records a VEX statement for one finding, shows its history,
 * and — once a statement exists — generates the CSAF form of it.
 *
 * ⚠ "APPLY TO" IS PICKED PER SUBMISSION, NOT PER FINDING ROW. A cluster can
 * affect several components (f.components); the same vulnerability might be
 * a real risk in one and absent in another (a vendored copy vs. a
 * dynamically-loaded one, say). Defaulting to "project-wide" is the
 * broadest, least-specific assertion — a reviewer narrowing it to one
 * component is a deliberate choice, not the default.
 */
function TriagePanel({ finding: f, projectId }: { finding: Finding; projectId: string }) {
  const firstComponent = f.components[0]?.key ?? '';
  const [scope, setScope] = useState<VEXScope>('project');
  const [componentKey, setComponentKey] = useState(firstComponent);
  const [status, setStatus] = useState<VEXStatus>('under_investigation');
  const [justification, setJustification] = useState('');
  const [remediation, setRemediation] = useState('');
  const [workarounds, setWorkarounds] = useState('');
  const [downtime, setDowntime] = useState('');

  const create = useCreateVEXStatement(projectId);
  const effectiveComponentKey = scope === 'project' ? '' : componentKey;
  const history = useVEXHistory(projectId, f.clusterId, effectiveComponentKey);
  const generateCSAF = useGenerateCSAFAdvisory(projectId);
  const advisories = useCSAFAdvisories(projectId);

  const latestStatement = history.data?.statements.filter((s) => !s.superseded_by).at(-1);
  const existingAdvisory = advisories.data?.advisories.find(
    (a) => a.vex_statement_id === latestStatement?.id,
  );

  return (
    <div className="panel">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const input: CreateVEXStatementInput = {
            cluster_id: f.clusterId,
            scope,
            status,
            ...(effectiveComponentKey && { component_key: effectiveComponentKey }),
            ...(justification && { justification }),
            ...(remediation && { remediation }),
            ...(workarounds && { workarounds }),
            ...(downtime && { downtime }),
          };
          create.mutate(input);
        }}
      >
        <label className="field">
          <span>Applies to</span>
          <select value={scope} onChange={(e) => setScope(e.target.value as VEXScope)}>
            {VEX_SCOPES.map((s) => (
              <option key={s} value={s}>
                {s === 'project' ? 'Whole project' : s}
              </option>
            ))}
          </select>
        </label>
        {scope !== 'project' && (
          <label className="field">
            <span>Component</span>
            <select value={componentKey} onChange={(e) => setComponentKey(e.target.value)}>
              {f.components.map((c) => (
                <option key={c.key} value={c.key}>
                  {c.name} {c.version}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="field">
          <span>Status</span>
          <select value={status} onChange={(e) => setStatus(e.target.value as VEXStatus)}>
            {VEX_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
        </label>
        {status === 'not_affected' && (
          <label className="field">
            <span>Justification (required for not affected)</span>
            <select value={justification} onChange={(e) => setJustification(e.target.value)}>
              <option value="">—</option>
              {VEX_JUSTIFICATIONS.map((j) => (
                <option key={j} value={j}>
                  {j.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="field">
          <span>Remediation</span>
          <input type="text" value={remediation} onChange={(e) => setRemediation(e.target.value)} />
        </label>
        <label className="field">
          <span>Workarounds</span>
          <input type="text" value={workarounds} onChange={(e) => setWorkarounds(e.target.value)} />
        </label>
        <label className="field">
          <span>Downtime</span>
          <input type="text" value={downtime} onChange={(e) => setDowntime(e.target.value)} />
        </label>
        <div className="step-actions">
          <button type="submit" className="btn btn-primary" disabled={create.isPending}>
            Record statement
          </button>
        </div>
        {create.isError && <p className="status status-down">{create.error.message}</p>}
      </form>

      <h3>History</h3>
      {history.isPending && <p className="field-hint">Loading…</p>}
      {history.data && history.data.statements.length === 0 && (
        <p className="field-hint">No statements recorded yet for this scope.</p>
      )}
      {history.data && history.data.statements.length > 0 && (
        <ul>
          {history.data.statements.map((s) => (
            <li key={s.id}>
              <strong>{s.status.replace(/_/g, ' ')}</strong> (v{s.version})
              {s.superseded_by ? ' — superseded' : ' — current'} · {s.justification || 'no justification'}{' '}
              · {new Date(s.created_at).toLocaleString()}
            </li>
          ))}
        </ul>
      )}

      {latestStatement && !latestStatement.superseded_by && (
        <div>
          <h3>CSAF</h3>
          {existingAdvisory ? (
            <p className="field-hint">
              Published as <code>{existingAdvisory.tracking_id}</code> on{' '}
              {new Date(existingAdvisory.created_at).toLocaleString()}.
            </p>
          ) : (
            <button
              type="button"
              className="btn"
              disabled={generateCSAF.isPending}
              onClick={() =>
                generateCSAF.mutate({
                  vex_statement_id: latestStatement.id,
                  cluster_display_id: f.displayId,
                  cluster_aliases: f.aliases,
                  component_name: f.components.find((c) => c.key === effectiveComponentKey)?.name ?? '',
                  component_purl: effectiveComponentKey,
                })
              }
            >
              Generate CSAF advisory
            </button>
          )}
          {generateCSAF.isError && (
            <p className="status status-down">{generateCSAF.error.message}</p>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * fixCell renders the minimum fixed version, or says why it cannot.
 *
 * ⚠ `unknown` ORDERING MEANS WE HAVE NO COMPARATOR FOR THIS ECOSYSTEM, and the
 * minimum is therefore not a claim we can make. Showing the raw value anyway
 * would assert an ordering a lexical sort gets wrong for every ecosystem —
 * 1.10.0 sorts before 1.9.0, and 1.9.0 does not contain the fix.
 */
function fixCell(f: Finding) {
  if (!f.fixedInMin) return <span className="text-faint">no fix available</span>;
  if (f.fixOrdering === 'unknown') {
    return (
      <span
        className="fix-unknown"
        title="No version comparator exists for this ecosystem, so the lowest fixed version cannot be determined."
      >
        fix exists · lowest unknown
      </span>
    );
  }
  return <code>{f.fixedInMin}</code>;
}

/**
 * ConflictDetail shows who said what.
 *
 * Every source is retained — that is the point. The table is deliberately plain
 * because the content is the argument: four rows with four different scales,
 * which is why the product refuses to average them.
 */
function ConflictDetail({ sources }: { sources: SeveritySource[] }) {
  return (
    <div className="conflict-panel">
      <p>
        These engines assessed the same vulnerability differently. AxeBOM does not average or take
        the maximum: CVSS v2, v3.1 and v4.0 use different formulas and ranges and{' '}
        <strong>are not comparable</strong>. The precedence-selected value is shown in the row;
        every source is here.
      </p>
      <table className="table table-compact">
        <thead>
          <tr>
            <th scope="col">Engine</th>
            <th scope="col">Severity</th>
            <th scope="col">CVSS</th>
            <th scope="col">Vector</th>
          </tr>
        </thead>
        <tbody>
          {sources.map((s, i) => (
            <tr key={`${s.engine}-${i}`}>
              <th scope="row">{s.engine}</th>
              <td>
                <SeverityBadge severity={s.severity} />
              </td>
              <td>
                {s.cvssScore ? (
                  `${s.cvssScore} (v${s.cvssVersion})`
                ) : (
                  <span className="text-faint">—</span>
                )}
              </td>
              <td>
                <code>
                  <Value>{s.cvssVector}</Value>
                </code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
