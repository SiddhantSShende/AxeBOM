/**
 * The hardware tree, and the form that completes it.
 *
 * ⚠ THE FOUR JUDGEMENT FIELDS ARE SURFACED, NOT HIDDEN BEHIND "ADVANCED".
 *
 * Warranty, licence terms, test result and criticality appear in no CAD or ERP
 * export. If the UI treats them as optional extras, they stay `not-provided`
 * forever and the customer's coverage number is permanently low for a reason
 * nothing on screen explains. §10.4.1.4 requires the criticality rating for
 * hardware supplied to government and public-sector entities, so the gap is not
 * cosmetic.
 */

import { useState } from 'react';
import { useParams } from 'react-router';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import {
  CRITICALITY_VALUES,
  JUDGEMENT_FIELDS,
  describeProvenance,
  flatten,
  useHardwareTree,
  usePartLookup,
  usePartProvider,
  useSaveComponent,
  type HardwareComponent,
} from '../../lib/hbom';

export function HardwareTree() {
  const { id: projectId = '' } = useParams();
  const { data: roots, isPending, error, refetch } = useHardwareTree(projectId);
  const provider = usePartProvider();
  const lookup = usePartLookup();

  const [editing, setEditing] = useState<HardwareComponent | null>(null);

  if (isPending) return <SkeletonRows rows={8} columns={6} />;
  if (error) {
    return (
      <ErrorState error={error} action="load this hardware BOM" onRetry={() => void refetch()} />
    );
  }

  if (!roots || roots.length === 0) {
    return (
      <EmptyState
        title="No hardware recorded yet"
        guidance={
          'Hardware is not discoverable by any scanner, so this starts from a parts list ' +
          'you already have — or from the form, one component at a time.'
        }
      />
    );
  }

  const rows = flatten(roots);
  const partNumbers = rows.map((r) => r.component.model_number).filter(Boolean);

  return (
    <section>
      <header className="page-header">
        <div>
          <h1>Hardware</h1>
          <p className="muted">
            {rows.length} components, imported from structured entry. Nothing here was
            discovered by a scan.
          </p>
        </div>

        {/*
          ⚠ THE LOOKUP CONTROL IS ABSENT WHEN NO PROVIDER IS CONFIGURED, rather
          than present and failing. A button that errors every time teaches
          people to ignore errors — and part lookup is optional by design,
          because requiring a commercial parts database would make HBOM unusable
          for somebody recording hardware they already own.
        */}
        {provider.data?.configured && (
          <button
            type="button"
            className="btn"
            disabled={lookup.isPending || partNumbers.length === 0}
            onClick={() => lookup.mutate(partNumbers)}
          >
            {lookup.isPending
              ? 'Looking up…'
              : `Look up ${partNumbers.length} parts via ${provider.data.provider}`}
          </button>
        )}
      </header>

      <MissingJudgements rows={rows} />

      <table className="table">
        <caption className="sr-only">Hardware component tree</caption>
        <thead>
          <tr>
            <th scope="col">Component</th>
            <th scope="col">Part number</th>
            <th scope="col">Qty</th>
            <th scope="col">Manufacturer</th>
            <th scope="col">Origin</th>
            <th scope="col">Criticality</th>
            <th scope="col">Provenance</th>
            <th scope="col">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ component, depth }) => (
            <tr key={component.id}>
              <th scope="row">
                <span aria-hidden="true" className="muted">
                  {'· '.repeat(depth)}
                </span>
                {component.product_name}
              </th>
              <td>{component.model_number || <NotProvided />}</td>
              <td>{component.quantity}</td>
              <td>{component.manufacturer_name || <NotProvided />}</td>
              <td>{component.origin || <NotProvided />}</td>
              <td>{component.criticality || <NotProvided />}</td>
              <td className="muted">{describeProvenance(component)}</td>
              <td>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => setEditing(component)}
                >
                  Complete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {editing && (
        <ComponentForm
          projectId={projectId}
          component={editing}
          onDone={() => setEditing(null)}
        />
      )}
    </section>
  );
}

/**
 * MissingJudgements says WHY the coverage number is what it is.
 *
 * ⚠ A CUSTOMER LOOKING AT 62% DESERVES TO KNOW that some of the gap is questions
 * only they can answer, rather than something the import failed to find. Without
 * this, a low number reads as a product defect and the fields never get filled.
 */
function MissingJudgements({
  rows,
}: {
  rows: Array<{ component: HardwareComponent; depth: number }>;
}) {
  const gaps = JUDGEMENT_FIELDS.map((f) => ({
    ...f,
    missing: rows.filter(({ component }) => !component[f.id as keyof HardwareComponent]).length,
  })).filter((f) => f.missing > 0);

  if (gaps.length === 0) return null;

  return (
    <div className="callout callout-warn">
      <h3>What a parts list cannot tell us</h3>
      <p>
        These are judgements about your hardware, and they appear in no CAD or ERP export.
        CERT-In §10.4.1.4 requires a criticality rating for hardware supplied to government
        and public-sector entities.
      </p>
      <ul>
        {gaps.map((g) => (
          <li key={g.id}>
            <strong>{g.label}</strong> — missing on {g.missing} of {rows.length}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ComponentForm({
  projectId,
  component,
  onDone,
}: {
  projectId: string;
  component: HardwareComponent;
  onDone: () => void;
}) {
  const save = useSaveComponent(projectId);
  const [draft, setDraft] = useState(component);

  function set<K extends keyof HardwareComponent>(key: K, value: HardwareComponent[K]) {
    setDraft({ ...draft, [key]: value });
  }

  return (
    <form
      className="panel"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate(draft, { onSuccess: onDone });
      }}
    >
      <h2>{component.product_name}</h2>

      {save.error && <ErrorState error={save.error} action="save this component" />}

      <div className="field-row">
        <label htmlFor="crit">Criticality</label>
        <select
          id="crit"
          value={draft.criticality}
          onChange={(e) => set('criticality', e.target.value as HardwareComponent['criticality'])}
        >
          <option value="">not-provided</option>
          {CRITICALITY_VALUES.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <p className="field-hint">Required by §10.4.1.4 for government and public-sector supply.</p>
      </div>

      <div className="field-row">
        <label htmlFor="warranty">Warranty / AMC</label>
        <input
          id="warranty"
          value={draft.warranty_amc}
          onChange={(e) => set('warranty_amc', e.target.value)}
        />
      </div>

      <div className="field-row">
        <label htmlFor="licence">Licence terms</label>
        <input
          id="licence"
          value={draft.license_info}
          onChange={(e) => set('license_info', e.target.value)}
        />
        <p className="field-hint">IP licences or usage terms, particularly for firmware.</p>
      </div>

      <div className="field-row">
        <label htmlFor="test">Test result</label>
        <input
          id="test"
          value={draft.test_result}
          onChange={(e) => set('test_result', e.target.value)}
        />
      </div>

      {/*
        ⚠ THE TWO SUPPLIER RELATIONSHIPS ARE LABELLED, NOT LEFT TO GUESSWORK.
        "Supplier" alone is the field somebody fills in with whichever company
        comes to mind, and the two mean different things in Table 11.
      */}
      <div className="field-row">
        <label htmlFor="prod-sup">Product supplier</label>
        <input
          id="prod-sup"
          value={draft.supplier_info}
          onChange={(e) => set('supplier_info', e.target.value)}
        />
        <p className="field-hint">Who sold YOU this product.</p>
      </div>

      <div className="field-row">
        <label htmlFor="comp-sup">Component supplier</label>
        <input
          id="comp-sup"
          value={draft.component_supplier_info}
          onChange={(e) => set('component_supplier_info', e.target.value)}
        />
        <p className="field-hint">
          Who supplied this part to the manufacturer of the larger product. A different
          relationship — CERT-In Table 11 records both.
        </p>
      </div>

      <div className="wizard-actions">
        <button type="submit" className="btn btn-primary" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save'}
        </button>
        <button type="button" className="btn" onClick={onDone}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function NotProvided() {
  return <span className="not-provided">not-provided</span>;
}
