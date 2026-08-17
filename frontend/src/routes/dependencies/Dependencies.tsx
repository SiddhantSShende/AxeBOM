/**
 * The dependencies explorer — the densest screen in the product.
 *
 * ⚠ VIRTUALIZED, BECAUSE 50k ROWS IS THE DESIGN CASE AND NOT THE EDGE ONE.
 *
 * A monorepo yields 50k+ components. Rendering that many DOM nodes freezes the
 * tab for seconds and then scrolls at single-digit frame rates, which makes the
 * screen useless for the one thing it is for: finding a component quickly.
 *
 * ⚠ FILTERS ARE URL STATE, so a view is shareable. "Everything GPL with a
 * critical finding" is a thing one person sends another, and a filter held only
 * in React state makes that impossible.
 *
 * docs/07-FRONTEND-SPEC.md §6.
 */

import { useMemo, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { useVirtualizer } from '@tanstack/react-virtual';
import { api } from '../../lib/api';
import { ProvenanceChips, SeverityBadge, Value } from '../../components/Chips';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { compareSeverity } from '../../design/theme';
import { ComponentDrawer, type ComponentDetail } from './ComponentDrawer';

export interface DependencyRow {
  key: string;
  name: string;
  version: string;
  ecosystem: string;
  license: string;
  isDirect: boolean;
  isOrphan: boolean;
  depth: number | null;
  criticality: string;
  topSeverity: string;
  findingCount: number;
  detectedBy: string[];
}

const ROW_HEIGHT = 32;

export function Dependencies() {
  const { id = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<string | null>(null);

  // ⚠ MEMOIZED ON THE SEARCH STRING, NOT REBUILT EACH RENDER. A fresh object
  // every render makes every downstream memo useless — the filter and sort over
  // 50k rows would recompute on any state change anywhere on the page, which is
  // exactly what the memo exists to prevent.
  const filters = useMemo(
    (): FilterState => ({
      q: params.get('q') ?? '',
      license: params.get('license') ?? '',
      severity: params.get('severity') ?? '',
      scope: params.get('scope') ?? '',
      ecosystem: params.get('ecosystem') ?? '',
      engine: params.get('engine') ?? '',
    }),
    [params],
  );

  const setFilter = (name: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    // ⚠ REPLACE, NOT PUSH. Typing in a search box would otherwise put one
    // history entry per keystroke, and Back would walk the user letter by
    // letter out of a filter they set deliberately.
    setParams(next, { replace: true });
  };

  const query = useQuery({
    queryKey: ['dependencies', id],
    queryFn: () => api.get<{ components: DependencyRow[] }>(`/v1/projects/${id}/dependencies`),
    staleTime: 30_000,
  });

  const rows = useMemo(
    () => applyFilters(query.data?.components ?? [], filters),
    [query.data, filters],
  );

  const detail = useQuery({
    queryKey: ['component', id, selected],
    queryFn: () =>
      api.get<ComponentDetail>(
        `/v1/projects/${id}/dependencies/${encodeURIComponent(selected ?? '')}`,
      ),
    enabled: selected !== null,
    // Component detail is immutable for a given normalization version, so
    // refetching it costs a request and changes nothing.
    staleTime: Infinity,
  });

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    // A generous overscan keeps fast scrolling from showing blank bands, at
    // the cost of a few dozen extra nodes.
    overscan: 16,
  });

  if (query.isPending) return <SkeletonRows rows={12} columns={7} />;
  if (query.isError) {
    return (
      <ErrorState
        error={query.error}
        action="load this project's dependencies"
        onRetry={() => void query.refetch()}
      />
    );
  }

  const total = query.data?.components.length ?? 0;

  return (
    <div className="deps">
      <Filters filters={filters} rows={query.data?.components ?? []} onChange={setFilter} />

      <p className="deps-count" role="status">
        {rows.length === total ? (
          <>
            <strong>{total}</strong> components
          </>
        ) : (
          <>
            <strong>{rows.length}</strong> of {total} components match
          </>
        )}
      </p>

      {total === 0 && (
        <EmptyState
          title="No components yet"
          guidance="This project has no normalized scan results. Run a scan, and the inventory appears as engines report."
        />
      )}

      {total > 0 && rows.length === 0 && (
        <EmptyState
          title="Nothing matches those filters"
          guidance="Every component was filtered out. Clearing one filter usually brings back what you were looking for."
          action={
            <button
              type="button"
              className="btn btn-quiet"
              onClick={() => setParams(new URLSearchParams())}
            >
              Clear all filters
            </button>
          }
        />
      )}

      {rows.length > 0 && (
        <div className="table-scroll" ref={scrollRef}>
          <table className="table table-virtual">
            <thead>
              <tr>
                <th scope="col">Component</th>
                <th scope="col">Version</th>
                <th scope="col">Ecosystem</th>
                <th scope="col">License</th>
                <th scope="col">Scope</th>
                <th scope="col">Severity</th>
                <th scope="col">Discovered by</th>
              </tr>
            </thead>
            <tbody style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
              {virtualizer.getVirtualItems().map((v) => {
                const row = rows[v.index]!;
                return (
                  <tr
                    key={row.key}
                    className="row-clickable"
                    style={{
                      position: 'absolute',
                      top: 0,
                      transform: `translateY(${v.start}px)`,
                      height: ROW_HEIGHT,
                      width: '100%',
                    }}
                    onClick={() => setSelected(row.key)}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      // ⚠ THE ROW IS KEYBOARD-OPERABLE. A click-only row makes
                      // the densest screen in the product unreachable without a
                      // mouse, and this is the screen a compliance reviewer
                      // spends the most time in.
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelected(row.key);
                      }
                    }}
                  >
                    <th scope="row">{row.name}</th>
                    <td>
                      <Value>{row.version}</Value>
                    </td>
                    <td>
                      <Value>{row.ecosystem}</Value>
                    </td>
                    <td>
                      <Value>{row.license}</Value>
                    </td>
                    <td>{scopeLabel(row)}</td>
                    <td>
                      {row.findingCount > 0 ? (
                        <SeverityBadge severity={row.topSeverity} count={row.findingCount} />
                      ) : (
                        <span className="text-faint">none</span>
                      )}
                    </td>
                    <td>
                      <ProvenanceChips engines={row.detectedBy} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selected !== null && (
        <ComponentDrawer
          componentKey={selected}
          detail={detail.data ?? null}
          loading={detail.isPending}
          error={detail.error}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

/**
 * scopeLabel says direct, transitive, or neither.
 *
 * ⚠ AN ORPHAN IS ITS OWN LABEL, NOT "transitive". A component no root reaches
 * has no known position in the tree; calling it transitive asserts one, and
 * calling it direct inflates the direct-dependency count — the headline number
 * a Top-Level report is built on.
 */
function scopeLabel(row: DependencyRow) {
  if (row.isOrphan || row.depth === null) {
    return (
      <span className="scope scope-orphan" title="No dependency root reaches this component.">
        unplaced
      </span>
    );
  }
  return (
    <span className={row.isDirect ? 'scope scope-direct' : 'scope scope-transitive'}>
      {row.isDirect ? 'direct' : `transitive · depth ${row.depth}`}
    </span>
  );
}

type FilterState = {
  q: string;
  license: string;
  severity: string;
  scope: string;
  ecosystem: string;
  engine: string;
};

function applyFilters(rows: DependencyRow[], f: FilterState): DependencyRow[] {
  const q = f.q.trim().toLowerCase();

  const filtered = rows.filter((r) => {
    if (q && !`${r.name} ${r.version} ${r.license} ${r.ecosystem}`.toLowerCase().includes(q)) {
      return false;
    }
    if (f.license && r.license !== f.license) return false;
    if (f.ecosystem && r.ecosystem !== f.ecosystem) return false;
    if (f.engine && !r.detectedBy.includes(f.engine)) return false;
    if (f.severity && r.topSeverity !== f.severity) return false;
    if (f.scope === 'direct' && !r.isDirect) return false;
    if (f.scope === 'transitive' && (r.isDirect || r.isOrphan)) return false;
    if (f.scope === 'unplaced' && !r.isOrphan) return false;
    return true;
  });

  // ⚠ MOST SEVERE FIRST, THEN NAME. The question this screen answers is "what
  // is broken", so a default sort by name would bury the answer 4,000 rows
  // down and make the filters mandatory rather than optional.
  return filtered.sort((a, b) => {
    const bySeverity = compareSeverity(a.topSeverity, b.topSeverity);
    if (bySeverity !== 0) return bySeverity;
    return a.name.localeCompare(b.name);
  });
}

function Filters({
  filters,
  rows,
  onChange,
}: {
  filters: FilterState;
  rows: DependencyRow[];
  onChange: (name: string, value: string) => void;
}) {
  const licenses = useMemo(() => distinct(rows.map((r) => r.license)), [rows]);
  const ecosystems = useMemo(() => distinct(rows.map((r) => r.ecosystem)), [rows]);
  const engines = useMemo(() => distinct(rows.flatMap((r) => r.detectedBy)), [rows]);

  return (
    <div className="filters">
      <label className="filter">
        <span>Search</span>
        <input
          type="search"
          value={filters.q}
          placeholder="name, version, licence"
          onChange={(e) => onChange('q', e.target.value)}
        />
      </label>

      <Select
        label="License"
        value={filters.license}
        options={licenses}
        onChange={(v) => onChange('license', v)}
      />
      <Select
        label="Severity"
        value={filters.severity}
        options={['critical', 'high', 'medium', 'low', 'unknown']}
        onChange={(v) => onChange('severity', v)}
      />
      <Select
        label="Scope"
        value={filters.scope}
        options={['direct', 'transitive', 'unplaced']}
        onChange={(v) => onChange('scope', v)}
      />
      <Select
        label="Ecosystem"
        value={filters.ecosystem}
        options={ecosystems}
        onChange={(v) => onChange('ecosystem', v)}
      />
      <Select
        label="Engine"
        value={filters.engine}
        options={engines}
        onChange={(v) => onChange('engine', v)}
      />
    </div>
  );
}

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="filter">
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Any</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function distinct(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}
