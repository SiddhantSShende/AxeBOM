/**
 * CSV import with column mapping and a preview.
 *
 * ⚠ THE PREVIEW IS NOT A COURTESY. IT IS THE STEP THAT MAKES THE MAPPING SAFE.
 *
 * A column mapping is a guess about somebody else's spreadsheet, and the two
 * most damaging ways to get it wrong are invisible in the resulting data: the
 * `level` column mapped to the wrong field (every part becomes a sibling of the
 * product), and the two supplier relationships swapped (the BOM asserts a
 * distributor sold the customer a gateway). Both produce structurally valid
 * output. Showing the tree BEFORE anything is stored is what lets a human catch
 * either one.
 *
 * ⚠ AND IT IS AN IMPORT. Nothing here scans. See lib/hbom.ts.
 */

import { useState, type ChangeEvent } from 'react';
import { useParams } from 'react-router';
import { ErrorState } from '../../components/States';
import {
  CANONICAL_COLUMNS,
  JUDGEMENT_FIELDS,
  flatten,
  useConfirmImport,
  usePreviewImport,
  useReadHeaders,
} from '../../lib/hbom';

export function HardwareImport() {
  const { id: projectId = '' } = useParams();

  const [file, setFile] = useState<File | null>(null);
  const [headers, setHeaders] = useState<string[]>([]);
  const [mapping, setMapping] = useState<Record<string, string>>({});

  const preview = usePreviewImport();
  const confirm = useConfirmImport(projectId);

  const [headerError, setHeaderError] = useState<string | null>(null);
  // How the server actually read the file, and which sheets a workbook holds.
  // Shown rather than inferred: a parts list on the second tab of a workbook is
  // otherwise an empty import with no explanation.
  const [fileMeta, setFileMeta] = useState<{ format: string; sheets: string[] } | null>(null);
  const headerReader = useReadHeaders();

  // ⚠ WRAPPED, NOT PASSED DIRECTLY. `onChange={handleFile}` on an async function
  // hands React a promise it does not await, so a rejection becomes an
  // unhandled rejection in the console and the user sees nothing at all —
  // which for a file that cannot be read is the least useful outcome available.
  function handleFile(event: ChangeEvent<HTMLInputElement>) {
    void readHeaders(event).catch((err: unknown) => {
      setHeaderError(err instanceof Error ? err.message : 'That file could not be read.');
    });
  }

  async function readHeaders(event: ChangeEvent<HTMLInputElement>) {
    setHeaderError(null);
    const chosen = event.target.files?.[0] ?? null;
    setFile(chosen);
    preview.reset();
    confirm.reset();
    if (!chosen) {
      setHeaders([]);
      return;
    }

    // ⚠ THE SERVER READS THE HEADER ROW, NOT THIS FUNCTION.
    //
    // This used to slice the first 64 KiB and split on commas, which works for
    // a CSV and for nothing else — a spreadsheet is a zip archive, so the
    // mapping screen below would have offered binary as the customer's column
    // names. The parser already lives on the server, next to the level-sequence
    // rule, for exactly the same reason: one implementation, in the place that
    // owns it.
    try {
      const meta = await headerReader.mutateAsync(chosen);
      setHeaders(meta.headers);
      setMapping(suggest(meta.headers));
      setFileMeta({ format: meta.format, sheets: meta.sheets });
    } catch (err) {
      setHeaders([]);
      setFileMeta(null);
      setHeaderError(
        err instanceof Error ? err.message : 'this file could not be read as a parts list',
      );
    }
  }

  const mappedTargets = new Set(Object.values(mapping).filter(Boolean));
  const missingLevel = !mappedTargets.has('level');

  return (
    <section>
      <header className="page-header">
        <div>
          <h1>Import a hardware BOM</h1>
          {/*
            ⚠ THE HONEST LABEL, AT THE TOP OF THE SCREEN THAT DOES THE WORK.
            Not buried in a tooltip, and not only in the generated report.
          */}
          {/* ⚠ THIS READ "Hardware is not discoverable by any scanner", which
              is the same under-claim the registration wizard carried: it reads
              as "AxeBOM cannot do hardware", and a design-file scan has existed
              since hbom-ecad shipped. The denial that must survive is narrower —
              nothing examines a PHYSICAL DEVICE. */}
          <p className="muted">
            Nothing here examined physical hardware — this reads a parts list you already have. A
            scan can also read design files you commit, or a report a collector produced on the
            device itself. Anything none of them covers, you can add by hand.
          </p>
        </div>
      </header>

      <div className="panel">
        <div className="field-row">
          <label htmlFor="hbom-file">Parts list</label>
          {/* ⚠ THIS ACCEPTED `.csv` AND NOTHING ELSE, which meant telling a
              customer to open their spreadsheet and re-save it before AxeBOM
              would read it — by hand, using a library already in the binary. */}
          <input
            id="hbom-file"
            type="file"
            accept=".csv,.tsv,.tab,.xlsx,.xlsm,text/csv,text/tab-separated-values,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            onChange={handleFile}
          />
          {headerError && (
            <p className="field-error" role="alert">
              {headerError}
            </p>
          )}
          <p className="field-hint">
            CSV, TSV or Excel. Your own export works as it is — the next step maps your column
            names. Do not edit the file to match ours; an edited export no longer matches your
            source of truth.
          </p>
          {fileMeta && (
            <p className="field-hint">
              Read as <strong>{fileMeta.format.toUpperCase()}</strong>
              {fileMeta.sheets.length > 1 && (
                <>
                  {' '}
                  — from the first sheet, <strong>{fileMeta.sheets[0]}</strong>. The others (
                  {fileMeta.sheets.slice(1).join(', ')}) were not read; move your parts list to the
                  first sheet if it is on one of them.
                </>
              )}
              .
            </p>
          )}
        </div>
      </div>

      {headers.length > 0 && (
        <div className="panel">
          <h2>Map your columns</h2>
          <p className="field-hint">
            Only <strong>Level</strong> is required. It is what builds the sub-component tree;
            without it every part becomes a sibling of the product rather than a part of it.
          </p>

          <table className="table">
            <caption className="sr-only">Column mapping</caption>
            <thead>
              <tr>
                <th scope="col">Your column</th>
                <th scope="col">Maps to</th>
              </tr>
            </thead>
            <tbody>
              {headers.map((header) => (
                <tr key={header}>
                  <th scope="row">
                    <code>{header}</code>
                  </th>
                  <td>
                    <label className="sr-only" htmlFor={`map-${header}`}>
                      What {header} maps to
                    </label>
                    <select
                      id={`map-${header}`}
                      value={mapping[header] ?? ''}
                      onChange={(e) => setMapping({ ...mapping, [header]: e.target.value })}
                    >
                      <option value="">— ignore this column —</option>
                      {CANONICAL_COLUMNS.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.label}
                          {c.required ? ' (required)' : ''}
                        </option>
                      ))}
                    </select>
                    {mapping[header] && hintFor(mapping[header]) && (
                      <p className="field-hint">{hintFor(mapping[header])}</p>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {missingLevel && (
            <p className="field-error" role="alert">
              No column is mapped to <strong>Level</strong>. Without it the import cannot build the
              sub-component tree.
            </p>
          )}

          <button
            type="button"
            className="btn btn-primary"
            disabled={!file || missingLevel || preview.isPending}
            onClick={() => file && preview.mutate({ file, mapping })}
          >
            {preview.isPending ? 'Reading…' : 'Preview the tree'}
          </button>
        </div>
      )}

      {preview.error && <ErrorState error={preview.error} action="read this parts list" />}

      {preview.data && (
        <div className="panel">
          <h2>Preview</h2>
          <p className="muted">
            {preview.data.component_count} components, {preview.data.max_depth + 1} levels. Nothing
            has been saved yet.
          </p>

          {/*
            ⚠ AN UNMAPPED HEADER IS SHOWN, NOT SWALLOWED. A customer whose
            "Criticality" column was spelled "Crit." would otherwise get a BOM
            missing a §10.4.1.4 element with nothing saying so.
          */}
          {preview.data.unmapped_headers.length > 0 && (
            <div className="callout callout-warn">
              <h3>Columns that were not imported</h3>
              <p>
                {preview.data.unmapped_headers.join(', ')} — map them above if they hold data you
                need, or leave them if they do not.
              </p>
            </div>
          )}

          {preview.data.warnings.length > 0 && (
            <div className="callout callout-warn">
              <h3>Worth checking</h3>
              <ul>
                {preview.data.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          <table className="table">
            <caption className="sr-only">Imported hardware tree preview</caption>
            <thead>
              <tr>
                <th scope="col">Depth</th>
                <th scope="col">Component</th>
                <th scope="col">Part number</th>
                <th scope="col">Qty</th>
                <th scope="col">Manufacturer</th>
                <th scope="col">Origin</th>
              </tr>
            </thead>
            <tbody>
              {flatten(preview.data.roots).map(({ component, depth }) => (
                <tr key={component.id || `${depth}-${component.model_number}`}>
                  <td>{depth}</td>
                  <td>
                    {/*
                      The indent is presentation only. The NAME is the name —
                      padding it with spaces would break search and would be one
                      more thing the spreadsheet export has to escape.
                    */}
                    <span aria-hidden="true" className="muted">
                      {'· '.repeat(depth)}
                    </span>
                    {component.product_name}
                  </td>
                  <td>{component.model_number || <NotProvided />}</td>
                  <td>{component.quantity}</td>
                  <td>{component.manufacturer_name || <NotProvided />}</td>
                  <td>{component.origin || <NotProvided />}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="callout">
            <h3>What a parts list cannot tell us</h3>
            <p>
              {JUDGEMENT_FIELDS.map((f) => f.label).join(', ')} appear in no CAD or ERP export —
              they are judgements about your hardware. CERT-In §10.4.1.4 requires a criticality
              rating for hardware supplied to government and public-sector entities. Add them per
              component after importing.
            </p>
          </div>

          <button
            type="button"
            className="btn btn-primary"
            disabled={!file || confirm.isPending}
            onClick={() => file && confirm.mutate({ file, mapping })}
          >
            {confirm.isPending ? 'Saving…' : 'Import these components'}
          </button>
        </div>
      )}

      {confirm.error && <ErrorState error={confirm.error} action="save this import" />}
      {confirm.data && (
        <div className="callout callout-ok" role="status">
          <h3>Imported</h3>
          <p>The hardware tree is saved. Add the judgement fields per component next.</p>
        </div>
      )}
    </section>
  );
}

function NotProvided() {
  // ⚠ EXPLICIT, NEVER A BLANK CELL. A blank reads as "we did not look";
  // `not-provided` says we looked and there was nothing. Both score zero for
  // completeness, but only one of them is honest about why.
  return <span className="not-provided">not-provided</span>;
}

function hintFor(columnId: string): string {
  return CANONICAL_COLUMNS.find((c) => c.id === columnId)?.hint ?? '';
}

/**
 * suggest proposes a mapping from a file's headers.
 *
 * ⚠ A PROPOSAL A HUMAN CONFIRMS, NEVER AN AUTOMATIC DECISION. Silently deciding
 * that a column called "Supplier" is the component supplier rather than the
 * product supplier puts data in the wrong one of the two relationships Table 11
 * distinguishes — which is precisely the mistake this screen exists to prevent.
 */
function suggest(headers: string[]): Record<string, string> {
  const aliases: Record<string, string> = {
    lvl: 'level',
    'bom level': 'level',
    indent: 'level',
    item: 'part_number',
    part: 'part_number',
    'part no': 'part_number',
    'part number': 'part_number',
    desc: 'description',
    qty: 'quantity',
    mfr: 'manufacturer',
    mfg: 'manufacturer',
    'manufacturer part number': 'mpn',
    'mfr part number': 'mpn',
    vendor: 'supplier',
    cost: 'unit_cost',
    'unit price': 'unit_cost',
  };

  const known = new Set(CANONICAL_COLUMNS.map((c) => c.id));
  const out: Record<string, string> = {};

  for (const header of headers) {
    const key = header.trim().toLowerCase();
    const underscored = key.replace(/\s+/g, '_');
    if (known.has(underscored as never)) out[header] = underscored;
    else if (aliases[key]) out[header] = aliases[key];
  }
  return out;
}
