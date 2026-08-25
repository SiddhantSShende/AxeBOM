/**
 * The component drawer.
 *
 * ⚠ THE TWO IDENTIFIERS ARE SHOWN SIDE BY SIDE AND LABELLED AS DIFFERENT
 * THINGS.
 *
 * `purl` is the canonical ecosystem identifier every scanner emits and all
 * deduplication runs on. The CERT-In Unique Identifier (§4.2 field 21) is a
 * different syntax — `pkg:supplier/Org/Name@1.0` — derived for presentation
 * only and never a merge key. They look similar enough that a reader shown one
 * will assume it is the other, which is how a downstream consumer ends up
 * deduplicating on a value nothing resolves.
 *
 * docs/07-FRONTEND-SPEC.md §6, CLAUDE.md invariant 4.
 */

import { Overlay } from '../../components/Overlay';
import { NotProvided, ProvenanceChips, Value } from '../../components/Chips';
import { ErrorState, SkeletonRows } from '../../components/States';

export interface ProfileFieldValue {
  fieldId: string;
  name: string;
  value: string;
  /** Which page of the guideline defines this field. */
  sourcePage: number;
  /** False for AxeBOM extensions, which cannot move a compliance number. */
  scored: boolean;
}

export interface ComponentDetail {
  key: string;
  purl: string;
  certinIdentifier: string;
  ecosystem: string;
  fields: ProfileFieldValue[];
  locations: string[];
  candidateIdentities: { kind: string; value: string; confidence: string; source: string }[];
  provenance: { engine: string; engineVersion: string; observedAt: string; rule: string }[];
}

export function ComponentDrawer({
  componentKey,
  detail,
  loading,
  error,
  onClose,
}: {
  componentKey: string;
  detail: ComponentDetail | null;
  loading: boolean;
  error: unknown;
  onClose: () => void;
}) {
  return (
    <Overlay variant="drawer" onClose={onClose} aria-label={`Component ${componentKey}`}>
      <header className="drawer-head">
        <h2>{detail?.fields.find((f) => f.name === 'Component Name')?.value ?? componentKey}</h2>
        <button type="button" className="btn btn-quiet" onClick={onClose} aria-label="Close">
          ✕
        </button>
      </header>

      {loading && <SkeletonRows rows={10} columns={2} />}
      {error != null && <ErrorState error={error} action="load this component" />}

      {detail && (
        <div className="drawer-body">
          <Identifiers detail={detail} />
          <ProfileFields fields={detail.fields} />
          <Locations locations={detail.locations} />
          <CandidateIdentities candidates={detail.candidateIdentities} />
          <Provenance entries={detail.provenance} />
        </div>
      )}
    </Overlay>
  );
}

function Identifiers({ detail }: { detail: ComponentDetail }) {
  return (
    <section>
      <h3>Identifiers</h3>
      {/*
        ⚠ TWO ROWS, TWO EXPLANATIONS, NEVER ONE COMBINED FIELD. The similarity
        of the two syntaxes is the whole hazard.
      */}
      <dl className="identifiers">
        <dt>
          Package URL <span className="tag">merge key</span>
        </dt>
        <dd>
          <code>
            <Value>{detail.purl}</Value>
          </code>
          <p className="field-note">
            The canonical ecosystem identifier. Every engine emits it and all deduplication runs on
            it — this is what makes one package reported by four scanners a single component.
          </p>
        </dd>

        <dt>
          CERT-In Unique Identifier <span className="tag tag-quiet">render only</span>
        </dt>
        <dd>
          <code>
            <Value>{detail.certinIdentifier}</Value>
          </code>
          <p className="field-note">
            CERT-In §4.2 field 21. A different syntax, derived from the supplier and name for the
            compliance document. It is <strong>not</strong> a resolvable Package URL and is never
            used to match components.
          </p>
        </dd>
      </dl>
    </section>
  );
}

/**
 * ProfileFields renders EVERY field in the profile, present or not.
 *
 * ⚠ ABSENT FIELDS ARE LISTED, NOT OMITTED. A drawer that shows only what it
 * has looks complete at 30% coverage — the reader cannot see the shape of what
 * is missing. Rendering `not-provided` explicitly is what makes a gap legible,
 * and it is the same rule the report writers follow (CLAUDE.md invariant 3).
 *
 * The count is never written anywhere: the list comes from the server, which
 * generates it from the profile.
 */
function ProfileFields({ fields }: { fields: ProfileFieldValue[] }) {
  const provided = fields.filter((f) => f.value && f.value !== 'not-provided').length;

  return (
    <section>
      <h3>
        CERT-In fields{' '}
        <span className="count">
          {provided} of {fields.length} with a substantive value
        </span>
      </h3>
      <p className="field-note">
        `not-provided` is recorded and reported, and it scores zero for completeness. It means we
        looked and there was nothing — which is a different statement from a field this tool does
        not collect.
      </p>
      <dl className="fields">
        {fields.map((f) => (
          <div key={f.fieldId} className="def-row">
            <dt>
              {f.name}
              {!f.scored && <span className="tag tag-quiet">extension</span>}
              <span className="field-source">p.{f.sourcePage}</span>
            </dt>
            <dd>{f.value && f.value !== 'not-provided' ? f.value : <NotProvided />}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

/**
 * Locations lists every path the component was seen at.
 *
 * ⚠ IDENTITY IS THE PACKAGE; LOCATIONS ARE 1:N. The same library appearing in
 * three lockfiles is one component seen three times, not three components —
 * and a reviewer chasing a finding needs all three paths, not the first one.
 */
function Locations({ locations }: { locations: string[] }) {
  return (
    <section>
      <h3>
        Locations <span className="count">{locations.length}</span>
      </h3>
      {locations.length === 0 ? (
        <NotProvided />
      ) : (
        <ul className="paths">
          {locations.map((l) => (
            <li key={l}>
              <code>{l}</code>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * CandidateIdentities are matches we did NOT merge on.
 *
 * ⚠ SHOWN, NOT HIDDEN, AND NEVER MERGED SILENTLY. A low-confidence CPE from
 * Dependency-Check attached to a PURL-identified component would inherit that
 * engine's false positives into the canonical record. Attaching it as a
 * candidate keeps the evidence visible while keeping it out of the merge.
 */
function CandidateIdentities({
  candidates,
}: {
  candidates: ComponentDetail['candidateIdentities'];
}) {
  if (candidates.length === 0) return null;

  return (
    <section>
      <h3>Candidate identities</h3>
      <p className="field-note">
        Other identifiers that may refer to this component. They were <strong>not</strong> merged
        into it — a low-confidence match folded into a canonical record inherits its source's false
        positives.
      </p>
      <table className="table table-compact">
        <thead>
          <tr>
            <th scope="col">Kind</th>
            <th scope="col">Value</th>
            <th scope="col">Confidence</th>
            <th scope="col">Source</th>
          </tr>
        </thead>
        <tbody>
          {candidates.map((c) => (
            <tr key={`${c.kind}:${c.value}`}>
              <td>{c.kind}</td>
              <td>
                <code>{c.value}</code>
              </td>
              <td>{c.confidence}</td>
              <td>{c.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

/**
 * Provenance is the chain of who observed what, and under which rule.
 *
 * This is what makes a merged component explainable: a reviewer asking "why is
 * this one row" gets the engines, their versions, and the identity rule that
 * fired — rather than being asked to trust the deduplication.
 */
function Provenance({ entries }: { entries: ComponentDetail['provenance'] }) {
  return (
    <section>
      <h3>Provenance</h3>
      {entries.length === 0 ? (
        <NotProvided />
      ) : (
        <>
          <ProvenanceChips engines={entries.map((e) => e.engine)} />
          <table className="table table-compact">
            <thead>
              <tr>
                <th scope="col">Engine</th>
                <th scope="col">Version</th>
                <th scope="col">Observed</th>
                <th scope="col">Identity rule</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={`${e.engine}-${i}`}>
                  <th scope="row">{e.engine}</th>
                  <td>
                    <Value>{e.engineVersion}</Value>
                  </td>
                  <td>{e.observedAt}</td>
                  <td>
                    <code>{e.rule}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
