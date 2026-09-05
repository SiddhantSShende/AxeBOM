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
import { Link, useParams } from 'react-router';
import { DeviceRegister } from './DeviceRegister';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import {
  JUDGEMENT_FIELDS,
  SUPPLIER_FORMATS,
  bySupplier,
  describeAlternate,
  type HardwareAlternate,
  describeProvenance,
  flatten,
  rollUp,
  strandedParts,
  toCSV,
  useHardwareTree,
  usePartLookup,
  usePartProvider,
  useComponentForm,
  useSaveComponent,
  type ComponentFormField,
  blankAlternate,
  blankComponent,
  normalizeAlternates,
  alternateWarning,
  EQUIVALENCE_VALUES,
  LIFECYCLE_VALUES,
  type HardwareComponent,
  type SupplierFormat,
} from '../../lib/hbom';

/**
 * The three lenses on one parts list.
 *
 * ⚠ ONE FORTY-COLUMN TABLE WOULD BE COMPLETE AND UNREADABLE. The split is by
 * AUDIENCE, and it is the same split the XLSX makes: compliance reads
 * provenance, assembly reads placements, purchasing reads cost and
 * availability. A reader who has to scroll horizontally past twenty columns
 * they do not need is a reader who stops looking.
 */
type View = 'compliance' | 'engineering' | 'procurement';

const VIEWS: { id: View; label: string; hint: string }[] = [
  { id: 'compliance', label: 'Provenance', hint: 'Where each part came from — CERT-In §10.2.1.' },
  { id: 'engineering', label: 'Engineering', hint: 'What goes where on the board.' },
  { id: 'procurement', label: 'Procurement', hint: 'What to buy, from whom, at what price.' },
];

export function HardwareTree() {
  const { id: projectId = '' } = useParams();
  const { data: roots, isPending, error, refetch } = useHardwareTree(projectId);
  const provider = usePartProvider();
  const lookup = usePartLookup();

  const [editing, setEditing] = useState<HardwareComponent | null>(null);
  const [view, setView] = useState<View>('compliance');

  if (isPending) return <SkeletonRows rows={8} columns={6} />;
  if (error) {
    return (
      <ErrorState error={error} action="load this hardware BOM" onRetry={() => void refetch()} />
    );
  }

  if (!roots || roots.length === 0) {
    return (
      <>
        <DeviceRegister projectId={projectId} />
        {/* ⚠ THE FORM HAS TO RENDER IN THIS BRANCH TOO. The empty state's own
            "Add a component" button sets `editing` — and this branch returns
            before the editor further down is ever reached, so without this the
            button appeared to do nothing at all. */}
        {editing && (
          <ComponentForm
            projectId={projectId}
            component={editing}
            onDone={() => setEditing(null)}
          />
        )}
        <EmptyState
          title="No parts recorded yet"
          /* ⚠ THIS USED TO SAY "Hardware is not discoverable by any scanner",
             which reads as "AxeBOM cannot do hardware" and stopped being the
             whole truth when hbom-ecad shipped. The denial that must survive is
             narrower and sharper: nothing examines a PHYSICAL DEVICE. Design
             files, parts lists and host inventories are all documents somebody
             produced, and two of the three are parsed by a real scan. */
          guidance={
            'Nothing examined physical hardware — but a scan does read the design files you ' +
            'commit. Connect a repository with KiCad, Altium or OrCAD files, import a parts ' +
            'list, upload what a collector on the device reported, or add components by hand.'
          }
          action={
            <>
              <Link className="btn btn-primary" to={`/projects/${projectId}/hardware/import`}>
                Import a parts list
              </Link>{' '}
              <button type="button" className="btn" onClick={() => setEditing(blankComponent())}>
                Add a component
              </button>
            </>
          }
        />
      </>
    );
  }

  const rows = flatten(roots);
  const partNumbers = rows.map((r) => r.component.model_number).filter(Boolean);

  return (
    <section>
      {/* ⚠ THE DEVICE REGISTER SITS ABOVE THE PARTS, because that is the order
          the two facts exist in: a device is a thing you have, and a parts list
          is something you later say about it. The tree used to be the whole
          screen, which is why a project could only ever hold one. */}
      <DeviceRegister projectId={projectId} />

      <header className="page-header">
        <div>
          <h1>Hardware</h1>
          {/*
            ⚠ THIS USED TO READ "imported from structured entry". It was true
            while a CSV and a form were the only ways in, and a design-file scan
            now populates the same table. What must NOT change is the denial: no
            open-source tool inspects a device and enumerates its parts, and a
            reader who assumes otherwise finds out at an audit.
          */}
          <p className="muted">
            {rows.length} components. AxeBOM did not examine any hardware to produce this — every
            value came from a design file, a parts list, a form, or an inventory your own machine
            reported.
          </p>
        </div>

        {/*
          ⚠ THE LOOKUP CONTROL IS ABSENT WHEN NO PROVIDER IS CONFIGURED, rather
          than present and failing. A button that errors every time teaches
          people to ignore errors — and part lookup is optional by design,
          because requiring a commercial parts database would make HBOM unusable
          for somebody recording hardware they already own.
        */}
        {/* ⚠ THERE WAS NO WAY TO ADD A PART IN THE UI AT ALL. The API has
            always inserted when the id is empty — only the button was missing —
            so a customer whose parts list was not in an exportable file had no
            path into the product. */}
        <button type="button" className="btn" onClick={() => setEditing(blankComponent())}>
          Add a component
        </button>

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
      <StrandedParts roots={roots} />
      <CostSummary roots={roots} />

      {/*
        ⚠ A TAB LIST, NOT A COLUMN PICKER. A picker makes every reader build
        their own table and remember which columns they turned off; three named
        lenses mean two people looking at "Procurement" are looking at the same
        thing.
      */}
      <div className="segmented" role="tablist" aria-label="Hardware views">
        {VIEWS.map((v) => (
          <button
            key={v.id}
            type="button"
            role="tab"
            aria-selected={view === v.id}
            title={v.hint}
            onClick={() => setView(v.id)}
          >
            {v.label}
          </button>
        ))}
      </div>

      {view === 'procurement' && <SupplierExport roots={roots} />}

      <div className="table-wrap">
        <table className="table">
          <caption className="sr-only">Hardware component tree</caption>
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col">Part number</th>
              <th scope="col">Qty</th>
              {view === 'compliance' && (
                <>
                  <th scope="col">Manufacturer</th>
                  <th scope="col">Origin</th>
                  <th scope="col">Criticality</th>
                  <th scope="col">Provenance</th>
                </>
              )}
              {view === 'engineering' && (
                <>
                  <th scope="col">Designators</th>
                  <th scope="col">Footprint</th>
                  <th scope="col">Assembly</th>
                  <th scope="col">Fitted</th>
                </>
              )}
              {view === 'procurement' && (
                <>
                  <th scope="col">Supplier SKU</th>
                  <th scope="col">Supplier</th>
                  <th scope="col">Unit</th>
                  <th scope="col">Extended</th>
                  <th scope="col">Lifecycle</th>
                  <th scope="col">Alternates</th>
                </>
              )}
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
                {view === 'compliance' && (
                  <>
                    <td>{component.manufacturer_name || <NotProvided />}</td>
                    <td>{component.origin || <NotProvided />}</td>
                    <td>{component.criticality || <NotProvided />}</td>
                    <td className="muted">{describeProvenance(component)}</td>
                  </>
                )}
                {view === 'engineering' && (
                  <>
                    <td>
                      {component.designators.length > 0 ? (
                        component.designators.join(', ')
                      ) : (
                        <NotProvided />
                      )}
                    </td>
                    <td>{component.package_footprint || <NotProvided />}</td>
                    <td>{component.assembly_type || <NotProvided />}</td>
                    {/*
                    ⚠ "Fitted", NOT "DNP". A column headed with an initialism is
                    what a reader gets backwards, and backwards here means a
                    factory omitting a part the design needs.
                  */}
                    <td>{component.do_not_populate ? 'No — do not populate' : 'Yes'}</td>
                  </>
                )}
                {view === 'procurement' && (
                  <>
                    <td>{component.supplier_sku || <NotProvided />}</td>
                    <td>{component.preferred_supplier || <NotProvided />}</td>
                    <td>{component.unit_price || <NotProvided />}</td>
                    <td>{component.extended_price || <NotProvided />}</td>
                    <td>
                      <LifecycleBadge status={component.lifecycle_status} />
                    </td>
                    <td>
                      {component.alternates.length > 0 ? (
                        component.alternates.map(describeAlternate).join('; ')
                      ) : (
                        <NotProvided />
                      )}
                    </td>
                  </>
                )}
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
      </div>

      {editing && (
        <ComponentForm projectId={projectId} component={editing} onDone={() => setEditing(null)} />
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
        These are judgements about your hardware, and they appear in no CAD or ERP export. CERT-In
        §10.4.1.4 requires a criticality rating for hardware supplied to government and
        public-sector entities.
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
  const form = useComponentForm();
  const [draft, setDraft] = useState(component);

  function set<K extends keyof HardwareComponent>(key: K, value: HardwareComponent[K]) {
    setDraft({ ...draft, [key]: value });
  }

  /**
   * setField writes one generated field back onto the draft.
   *
   * ⚠ A LIST ELEMENT IS SPLIT BACK INTO AN ARRAY. The column is `text[]`, so
   * storing the raw "RoHS, CE" string would put one entry containing a comma
   * into it — which reads back as a single meaningless certification.
   */
  function setField(field: ComponentFormField, value: string) {
    if (field.list) {
      const parts = value
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);
      setDraft({ ...draft, [field.attr]: parts });
      return;
    }
    setDraft({ ...draft, [field.attr]: value });
  }

  return (
    <form
      className="panel"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate(
          { ...draft, alternates: normalizeAlternates(draft.alternates) },
          { onSuccess: onDone },
        );
      }}
    >
      {/* ⚠ A NEW COMPONENT HAS NO NAME YET, and rendering `product_name` blindly
          gave the create form an empty heading — a panel that appeared out of
          nowhere with no title. Caught by looking at it. */}
      <h2>{component.id === '' ? 'New component' : component.product_name}</h2>

      {save.error && <ErrorState error={save.error} action="save this component" />}

      {/* ⚠ SIX INPUTS USED TO BE HARDCODED HERE AND THE REST ROUND-TRIPPED
          UNTOUCHED — fetched, held in state, written back unchanged. A customer
          could see a `not-provided` manufacturer on the component sheet and had
          nowhere to fix it, and the coverage number stayed low for a reason
          nothing on screen explained. That is the failure MissingJudgements was
          written to prevent for four fields and nobody extended to the rest.

          The list now comes from the compliance profile, so a CERT-In revision
          adds an input without a frontend release (invariant 2). */}
      {form.isPending && <p className="field-hint">Loading the field list…</p>}
      {form.isError && <ErrorState error={form.error} action="load the field list" />}

      <div className="field-grid">
        {(form.data ?? []).map((field) => (
          <ComponentField
            key={field.attr}
            field={field}
            value={valueOf(draft, field)}
            onChange={(value) => setField(field, value)}
          />
        ))}
      </div>

      <AlternatesEditor
        alternates={draft.alternates}
        onChange={(alternates) => set('alternates', alternates)}
      />

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

/**
 * valueOf reads a form field's current value off the draft.
 *
 * ⚠ A LIST ELEMENT IS JOINED, NOT STRINGIFIED. Table 11's `compliance` holds
 * ["RoHS","CE"]; `String(...)` would render it as `RoHS,CE` by accident and
 * `[object Object]` the moment the shape changed.
 */
function valueOf(draft: HardwareComponent, field: ComponentFormField): string {
  const raw = (draft as unknown as Record<string, unknown>)[field.attr];
  if (Array.isArray(raw)) return raw.join(', ');
  return typeof raw === 'string' ? raw : '';
}

/** ComponentField renders one input described by the server. */
function ComponentField({
  field,
  value,
  onChange,
}: {
  field: ComponentFormField;
  value: string;
  onChange: (value: string) => void;
}) {
  const cite = field.source_page ? <small>CERT-In p.{field.source_page}</small> : null;

  return (
    <label className="field">
      <span>{field.name}</span>
      {field.values ? (
        <select value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">not-provided</option>
          {field.values.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      ) : field.multiline ? (
        <textarea rows={3} value={value} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input
          value={value}
          placeholder={field.list ? 'RoHS, CE' : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {field.hint && <small>{field.hint}</small>}
      {cite}
    </label>
  );
}

function NotProvided() {
  return <span className="not-provided">not-provided</span>;
}

/**
 * LifecycleBadge renders availability, and says what it means.
 *
 * ⚠ THE TITLE NAMES THE CONSEQUENCE, NOT THE STATUS. "obsolete" is a label
 * somebody has to look up; "cannot be bought" is the thing they act on. NRND is
 * the one most worth explaining — Not Recommended for New Designs is buyable
 * today and refused at the next respin, which is the window in which acting is
 * still cheap, and nothing about the word says that.
 */
function LifecycleBadge({ status }: { status: HardwareComponent['lifecycle_status'] }) {
  if (!status) return <NotProvided />;

  const meaning: Record<string, string> = {
    active: 'In production.',
    nrnd: 'Not Recommended for New Designs — buyable now, refused at the next respin.',
    obsolete: 'No longer manufactured.',
    eol: 'End of life — no longer manufactured.',
    preview: 'Pre-production. Availability and specification may still change.',
    unknown: 'No status was supplied. Not the same as active — nothing has been checked.',
  };
  // ⚠ THE DESIGN SYSTEM'S OWN STATUSES, NOT NEW ONES. `.pill[data-status]` has
  // ok/warn/down/info and nothing else; inventing a `badge-danger` would ship a
  // class with no CSS behind it, which renders as unstyled text and looks like
  // a bug rather than a warning.
  const tone: Record<string, string> = {
    active: 'ok',
    nrnd: 'warn',
    obsolete: 'down',
    eol: 'down',
    preview: 'info',
    unknown: 'info',
  };

  return (
    <span className="pill" data-status={tone[status] ?? 'info'} title={meaning[status] ?? ''}>
      {status}
    </span>
  );
}

/**
 * StrandedParts is the warning that justifies the whole Lifecycle column.
 *
 * ⚠ AN OBSOLETE PART WITH NO APPROVED ALTERNATE IS THE MOST ACTIONABLE FACT IN
 * A HARDWARE BOM, and it is one row among hundreds. Each one stops a build when
 * remaining stock runs out — and the cheapest moment to find a second source is
 * before it is needed, not after.
 */
function StrandedParts({ roots }: { roots: HardwareComponent[] }) {
  const stranded = strandedParts(roots);
  if (stranded.length === 0) return null;

  return (
    <aside className="callout callout-warn">
      <h3>
        {stranded.length} part{stranded.length === 1 ? '' : 's'} cannot be bought, with no recorded
        alternate
      </h3>
      <p className="muted">
        Each will stop a build when remaining stock runs out. Recording an approved second source
        now is far cheaper than finding one under a deadline.
      </p>
      <ul>
        {stranded.map((c) => (
          <li key={c.id}>
            <strong>{c.model_number || c.product_name}</strong>{' '}
            <span className="muted">
              ({c.lifecycle_status}
              {c.designators.length > 0 ? ` · ${c.designators.join(', ')}` : ''})
            </span>
          </li>
        ))}
      </ul>
    </aside>
  );
}

/**
 * CostSummary totals the parts list, per currency.
 *
 * ⚠ NEVER ACROSS CURRENCIES, AND ALWAYS WITH THE UNPRICED COUNT. 4.10 USD +
 * 3.20 EUR is not a number and there is no exchange rate here to make one. A
 * total over a list where half the prices are missing is not the cost of the
 * product, and a reader who is not told will read it as one — so the count is
 * rendered beside the figure rather than in a footnote.
 */
function CostSummary({ roots }: { roots: HardwareComponent[] }) {
  const { totals, unpriced } = rollUp(roots);
  if (totals.length === 0 && unpriced === 0) return null;

  return (
    <aside className="callout">
      <h3>Cost</h3>
      {totals.length === 0 ? (
        <p className="muted">No line carries a price.</p>
      ) : (
        <ul>
          {totals.map((t) => (
            <li key={t.currency}>
              <strong>
                {t.total} {t.currency}
              </strong>{' '}
              <span className="muted">
                across {t.lines} priced line{t.lines === 1 ? '' : 's'}
              </span>
            </li>
          ))}
        </ul>
      )}
      {unpriced > 0 && (
        <p className="muted">
          {unpriced} line{unpriced === 1 ? '' : 's'} carry no usable price and are not included in
          any total above.
        </p>
      )}
      {totals.length > 1 && (
        <p className="muted">
          No combined total: this BOM is priced in more than one currency, and there is no exchange
          rate in this data to combine them with.
        </p>
      )}
    </aside>
  );
}

/**
 * SupplierExport writes one order file per supplier.
 *
 * ⚠ THIS IS THE NATIVE REPLACEMENT FOR A GPL-3.0 PLUGIN WE DECLINED.
 * `KiCAD-Multi-BOM-Plugin` does the same job and is GPL-3.0, which invariant 9
 * forbids importing; the rejection and its reason are recorded in
 * OSINT/tools.manifest.yaml.
 *
 * ⚠ THE FILE IS BUILT AND DOWNLOADED IN THE BROWSER, never round-tripped
 * through the server. There is nothing to store: it is a projection of data the
 * page already holds, and a server round trip would only add a way for it to be
 * stale.
 */
function SupplierExport({ roots }: { roots: HardwareComponent[] }) {
  const [format, setFormat] = useState<SupplierFormat>('generic');
  const boms = bySupplier(roots, format);

  if (boms.length === 0) return null;

  const download = (supplier: string) => {
    const bom = boms.find((b) => b.supplier === supplier);
    if (!bom) return;
    const blob = new Blob([toCSV(bom)], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${supplier.replace(/[^\w.-]+/g, '-').toLowerCase()}-bom.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <aside className="callout">
      <h3>Order files</h3>
      <p className="muted">
        One file per supplier, in that supplier&rsquo;s own column layout. Do-not-populate parts are
        excluded — ordering them wastes money, and listing them on an assembly file tells a factory
        to place a part the design says to leave off.
      </p>

      <label>
        <span>Layout</span>
        <select value={format} onChange={(e) => setFormat(e.target.value as SupplierFormat)}>
          {SUPPLIER_FORMATS.map((f) => (
            <option key={f.id} value={f.id} title={f.hint}>
              {f.label}
            </option>
          ))}
        </select>
      </label>

      <div className="chips">
        {boms.map((b) => (
          <button
            key={b.supplier}
            type="button"
            className="btn btn-sm btn-quiet"
            onClick={() => download(b.supplier)}
          >
            {b.supplier} ({b.rows.length})
          </button>
        ))}
      </div>
    </aside>
  );
}

/**
 * AlternatesEditor manages a component's approved second sources.
 *
 * ⚠ THIS IS THE FIELD THAT DECIDES WHETHER AN OBSOLETE PART DELAYS A BUILD OR
 * STOPS IT, and until now it could only arrive by import — the API mapped it in
 * both directions and the store persisted it in neither, so anything typed here
 * would have been accepted and discarded.
 *
 * ⚠ EVERY ROW SHOWS ITS EQUIVALENCE, AND THE DEFAULT IS `unverified`. A part
 * number alone reads as an approved substitution. The single most damaging
 * thing this editor could do is let somebody record a candidate and have a
 * later reader treat it as a decision, so the qualifier is never optional and
 * never starts anywhere but the weakest value.
 */
function AlternatesEditor({
  alternates,
  onChange,
}: {
  alternates: HardwareAlternate[];
  onChange: (alternates: HardwareAlternate[]) => void;
}) {
  function update(index: number, patch: Partial<HardwareAlternate>) {
    onChange(alternates.map((a, i) => (i === index ? { ...a, ...patch } : a)));
  }

  return (
    <fieldset className="field-group">
      <legend>Approved alternates</legend>
      <p className="field-hint">
        Second sources for this part. A component that is obsolete with no alternate recorded will
        stop a build when remaining stock runs out.
      </p>

      {alternates.length === 0 && (
        <p className="empty-hint">No alternate recorded for this part.</p>
      )}

      {alternates.map((alternate, index) => {
        const warning = alternateWarning(alternate);
        return (
          <div key={index} className="alternate-row">
            <div className="field-row">
              <label htmlFor={`alt-mfr-${index}`}>Manufacturer</label>
              <input
                id={`alt-mfr-${index}`}
                value={alternate.manufacturer_name}
                onChange={(e) => update(index, { manufacturer_name: e.target.value })}
              />
            </div>

            <div className="field-row">
              <label htmlFor={`alt-mpn-${index}`}>Part number</label>
              <input
                id={`alt-mpn-${index}`}
                value={alternate.model_number}
                onChange={(e) => update(index, { model_number: e.target.value })}
              />
            </div>

            <div className="field-row">
              <label htmlFor={`alt-sku-${index}`}>Supplier SKU</label>
              <input
                id={`alt-sku-${index}`}
                value={alternate.supplier_sku}
                onChange={(e) => update(index, { supplier_sku: e.target.value })}
              />
            </div>

            <div className="field-row">
              <label htmlFor={`alt-sup-${index}`}>Supplier</label>
              <input
                id={`alt-sup-${index}`}
                value={alternate.supplier_info}
                onChange={(e) => update(index, { supplier_info: e.target.value })}
              />
            </div>

            <div className="field-row">
              <label htmlFor={`alt-equiv-${index}`}>Equivalence</label>
              <select
                id={`alt-equiv-${index}`}
                value={alternate.equivalence}
                onChange={(e) =>
                  update(index, {
                    equivalence: e.target.value as HardwareAlternate['equivalence'],
                  })
                }
              >
                {EQUIVALENCE_VALUES.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
              <p className="field-hint">
                <code>drop-in</code> replaces the part with no change. <code>functional</code> needs
                a design or firmware change. <code>unverified</code> means nobody has checked.
              </p>
            </div>

            <div className="field-row">
              <label htmlFor={`alt-life-${index}`}>Lifecycle</label>
              <select
                id={`alt-life-${index}`}
                value={alternate.lifecycle_status}
                onChange={(e) => update(index, { lifecycle_status: e.target.value })}
              >
                <option value="">not-provided</option>
                {LIFECYCLE_VALUES.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </div>

            <div className="field-row">
              <label htmlFor={`alt-note-${index}`}>Approval note</label>
              <input
                id={`alt-note-${index}`}
                value={alternate.approval_note}
                onChange={(e) => update(index, { approval_note: e.target.value })}
              />
              <p className="field-hint">Who approved it, and against what.</p>
            </div>

            {warning && <p className="field-warning">{warning}</p>}

            <button
              type="button"
              className="btn btn-quiet"
              onClick={() => onChange(alternates.filter((_, i) => i !== index))}
            >
              Remove this alternate
            </button>
          </div>
        );
      })}

      <button
        type="button"
        className="btn"
        onClick={() => onChange([...alternates, blankAlternate(alternates.length)])}
      >
        Add an alternate
      </button>
    </fieldset>
  );
}
