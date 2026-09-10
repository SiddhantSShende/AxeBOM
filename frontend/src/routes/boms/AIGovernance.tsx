/**
 * AI governance — the two consent switches, the operator's classifications, and
 * the signature checks that were actually run.
 *
 * ⚠ EVERY VALUE ON THIS SCREEN IS A PERSON'S DECISION, NOT A FINDING. Whether a
 * system is high-risk under the EU AI Act depends on what it is USED FOR, which
 * is not visible in a repository; AxeBOM cannot classify and does not try. It
 * records who declared what, and when, so the classification can be asked about
 * later. `declared_by` is on every row for that reason.
 *
 * ⚠ AND AxeBOM NEVER SAYS "COMPLIANT". A tier and a set of controls are what an
 * operator asserted, rendered back to them. The word does not appear here, in
 * the report, or anywhere else in generated output.
 */

import { Fragment, useState } from 'react';
import { ErrorState, SkeletonRows } from '../../components/States';
import { NotProvided } from '../../components/Chips';
import {
  useAIAttestations,
  useAIPolicy,
  useComplianceTags,
  useSaveComplianceTag,
  useSetAIPolicy,
  type AIModel,
} from '../../lib/aibom';

export function AIGovernance({ projectId, models }: { projectId: string; models: AIModel[] }) {
  return (
    <>
      <PolicyPanel projectId={projectId} />
      <TagsPanel projectId={projectId} models={models} />
      <AttestationsPanel projectId={projectId} />
    </>
  );
}

/**
 * PolicyPanel is the consent for the two engines that would send customer code
 * to a third party.
 *
 * ⚠ THE SWITCH AND WHETHER IT DOES ANYTHING ARE TWO DIFFERENT FACTS, AND BOTH
 * ARE SHOWN. Both engines need network egress the scan sandbox does not have
 * (invariant 7), so today consent is recorded and the engines stay off. A toggle
 * rendered without `effective` would tell a customer something started that did
 * not — which is the same class of lie as a coverage number counting
 * `not-provided`.
 */
function PolicyPanel({ projectId }: { projectId: string }) {
  const policy = useAIPolicy(projectId);
  const save = useSetAIPolicy(projectId);

  if (policy.isPending) return <SkeletonRows rows={2} columns={2} />;
  if (policy.isError) return <ErrorState error={policy.error} action="load the AI policy" />;
  const p = policy.data;
  if (!p) return null;

  const set = (patch: { llm_enrich_enabled?: boolean; cisco_enabled?: boolean }) =>
    save.mutate({
      llm_enrich_enabled: p.llm_enrich_enabled,
      cisco_enabled: p.cisco_enabled,
      ...patch,
    });

  return (
    <section className="panel" aria-labelledby="ai-policy-heading">
      <h2 id="ai-policy-heading">Third-party enrichment</h2>
      <p className="field-hint">
        Both of these send code context to a third party on every future scan. They are off by
        default, the decision is recorded against the person who made it, and turning one on is an
        admin action, not an analyst one.
      </p>
      <label className="field field-inline">
        <input
          type="checkbox"
          checked={p.llm_enrich_enabled}
          disabled={save.isPending}
          onChange={(e) => set({ llm_enrich_enabled: e.target.checked })}
        />
        <span>
          <strong>LLM enrichment</strong> — lets an AIBOM engine send source context to a hosted
          model to describe what it found.
        </span>
      </label>
      <label className="field field-inline">
        <input
          type="checkbox"
          checked={p.cisco_enabled}
          disabled={save.isPending}
          onChange={(e) => set({ cisco_enabled: e.target.checked })}
        />
        <span>
          <strong>Cisco AI Defense</strong> — its <code>analyze</code> command always requires an
          LLM, so there is no offline mode to fall back to.
        </span>
      </label>

      {!p.effective && (
        <p className="status status-warn" role="status">
          Recorded, and not in force.{' '}
          {p.blocker ??
            'Engines run with no network access, so nothing consented to here runs on a scan yet. The switch is kept because the decision is worth recording before the capability exists, not after.'}
        </p>
      )}
      {p.consent_recorded_by && (
        <p className="field-hint">
          Last changed by <code className="mono-sm">{p.consent_recorded_by}</code>
          {p.consent_recorded_at ? ` at ${p.consent_recorded_at}` : ''}.
        </p>
      )}
      {save.isError && <p className="status status-down">{save.error.message}</p>}
    </section>
  );
}

/** TagsPanel records the operator's own classification of each model. */
function TagsPanel({ projectId, models }: { projectId: string; models: AIModel[] }) {
  const tags = useComplianceTags(projectId);
  const [editing, setEditing] = useState<string | null>(null);

  if (tags.isPending) return <SkeletonRows rows={3} columns={4} />;
  if (tags.isError) return <ErrorState error={tags.error} action="load the AI classifications" />;
  const vocabulary = tags.data?.vocabulary;
  const byKey = new Map((tags.data?.tags ?? []).map((t) => [t.model_key, t]));

  // ⚠ THE PROJECT-WIDE TAG IS A REAL ROW WITH AN EMPTY KEY, not a missing one.
  // An AI system is classified as a system; per-model tiers are the exception.
  // Rendering it as a nameless model would be the wrong reading of real data.
  const rows: { key: string; label: string }[] = [
    { key: '', label: 'This project (whole AI system)' },
    ...models.map((m) => ({ key: m.model_key, label: m.model_name })),
  ];

  return (
    <section className="panel" aria-labelledby="ai-tags-heading">
      <h2 id="ai-tags-heading">Classification</h2>
      <p className="field-hint">
        Declared by you, not detected. AxeBOM has no way to know what a model is used for, and it
        reports what was declared against what a scan found — it never states that a system is
        compliant.
      </p>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Applies to</th>
              <th scope="col">EU AI Act tier</th>
              <th scope="col">NIST AI RMF</th>
              <th scope="col">ISO/IEC 42001</th>
              <th scope="col">Rationale</th>
              <th scope="col">Declared by</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {rows.map(({ key, label }) => {
              const tag = byKey.get(key);
              // ⚠ THE KEY GOES ON THE FRAGMENT, NOT THE ROWS INSIDE IT. React
              // keys the element `map` returns; keying the children instead
              // leaves the list unkeyed and React reuses the wrong expanded
              // form when a row is added above it.
              return (
                <Fragment key={key || 'project'}>
                  <tr>
                    <td title={key || undefined}>{label}</td>
                    <td>{tag?.eu_ai_act_tier ? tag.eu_ai_act_tier : <NotProvided />}</td>
                    <td>
                      {tag?.nist_ai_rmf?.length ? tag.nist_ai_rmf.join(', ') : <NotProvided />}
                    </td>
                    <td>{tag?.iso_42001?.length ? tag.iso_42001.join('; ') : <NotProvided />}</td>
                    <td>{tag?.rationale ? tag.rationale : <NotProvided />}</td>
                    <td>
                      {tag ? (
                        <span title={tag.updated_at}>
                          <code className="mono-sm">{tag.declared_by}</code>
                        </span>
                      ) : (
                        <NotProvided />
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn"
                        onClick={() => setEditing((v) => (v === key ? null : key))}
                      >
                        {editing === key ? 'Close' : tag ? 'Change' : 'Declare'}
                      </button>
                    </td>
                  </tr>
                  {editing === key && vocabulary && (
                    <tr>
                      <td colSpan={7}>
                        <TagForm
                          projectId={projectId}
                          modelKey={key}
                          current={tag}
                          vocabulary={vocabulary}
                          onDone={() => setEditing(null)}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

interface Vocabulary {
  eu_ai_act_tier: string[];
  nist_ai_rmf: string[];
  iso_42001: string[];
}

/**
 * TagForm offers only what the server's vocabulary allows.
 *
 * ⚠ THE OPTIONS COME FROM THE SERVER, NOT FROM A LIST HERE. `ValidateComplianceTag`
 * rejects anything outside its own sets, so a hardcoded option list here would
 * eventually offer a tier the API refuses — the Go-vs-SQL closed-set drift this
 * repository has now shipped twice, in the compliance tags and the report
 * formats. One set, sent over the wire, rendered.
 */
function TagForm({
  projectId,
  modelKey,
  current,
  vocabulary,
  onDone,
}: {
  projectId: string;
  modelKey: string;
  current:
    | { eu_ai_act_tier?: string; nist_ai_rmf: string[]; iso_42001: string[]; rationale?: string }
    | undefined;
  vocabulary: Vocabulary;
  onDone: () => void;
}) {
  const save = useSaveComplianceTag(projectId);
  const [tier, setTier] = useState(current?.eu_ai_act_tier ?? '');
  const [nist, setNist] = useState<string[]>(current?.nist_ai_rmf ?? []);
  const [iso, setIso] = useState<string[]>(current?.iso_42001 ?? []);
  const [rationale, setRationale] = useState(current?.rationale ?? '');

  const toggle = (list: string[], value: string) =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value];

  return (
    <form
      className="panel"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate(
          {
            model_key: modelKey,
            // Sent as empty strings rather than omitted: the server's
            // `nullIfEmpty` turns them back into NULL, and an omitted key on a
            // PUT that upserts the whole row would leave a previous tier in
            // place while the form showed it cleared.
            eu_ai_act_tier: tier,
            nist_ai_rmf: nist,
            iso_42001: iso,
            rationale,
          },
          { onSuccess: onDone },
        );
      }}
    >
      <label className="field">
        <span>EU AI Act risk tier</span>
        <select value={tier} onChange={(e) => setTier(e.target.value)}>
          <option value="">— not declared —</option>
          {vocabulary.eu_ai_act_tier.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </label>

      <fieldset className="field">
        <legend>NIST AI RMF functions</legend>
        {vocabulary.nist_ai_rmf.map((f) => (
          <label className="field-inline" key={f}>
            <input
              type="checkbox"
              checked={nist.includes(f)}
              onChange={() => setNist((v) => toggle(v, f))}
            />
            <span>{f}</span>
          </label>
        ))}
      </fieldset>

      <fieldset className="field">
        <legend>ISO/IEC 42001 Annex A controls</legend>
        {vocabulary.iso_42001.map((c) => (
          <label className="field-inline" key={c}>
            <input
              type="checkbox"
              checked={iso.includes(c)}
              onChange={() => setIso((v) => toggle(v, c))}
            />
            <span>{c}</span>
          </label>
        ))}
      </fieldset>

      <label className="field">
        <span>Rationale</span>
        <textarea
          rows={2}
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          placeholder="Why this tier. Recorded with your name against it."
        />
      </label>

      <div className="step-actions">
        <button type="submit" className="btn btn-primary" disabled={save.isPending}>
          Save
        </button>
        <button type="button" className="btn" onClick={onDone}>
          Cancel
        </button>
      </div>
      {save.isError && <p className="status status-down">{save.error.message}</p>}
    </form>
  );
}

/**
 * AttestationsPanel shows signature checks that were actually run.
 *
 * ⚠ A VERIFICATION RESULT, NEVER A SIGNATURE, AND NEVER A DEFAULT. An empty
 * table means nobody ran `model_signing verify` against these weights — it does
 * not mean the weights are unsigned, and it must not read as either a pass or a
 * failure. A model AxeBOM could not confirm stays `verified = false` and is
 * never enriched with a plausible-looking default.
 */
function AttestationsPanel({ projectId }: { projectId: string }) {
  const attestations = useAIAttestations(projectId);

  if (attestations.isPending) return <SkeletonRows rows={2} columns={4} />;
  if (attestations.isError) {
    return <ErrorState error={attestations.error} action="load the attestation records" />;
  }
  const rows = attestations.data?.attestations ?? [];

  return (
    <section className="panel" aria-labelledby="ai-attestations-heading">
      <h2 id="ai-attestations-heading">Attestations</h2>
      {rows.length === 0 ? (
        <p className="field-hint">
          No signature has been verified for this project. That is not a finding either way — it
          means nothing has been checked, and CERT-In element 19 stays <code>not-provided</code>.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="table-caption">
              The result of a check that ran, with who recorded it. AxeBOM stores no signatures.
            </caption>
            <thead>
              <tr>
                <th scope="col">Model</th>
                <th scope="col">Result</th>
                <th scope="col">Method</th>
                <th scope="col">Signer</th>
                <th scope="col">Issuer</th>
                <th scope="col">Digest</th>
                <th scope="col">Verified at</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={`${a.model_key}|${a.verified_at}`}>
                  <td>
                    <code className="mono-sm">{a.model_key}</code>
                  </td>
                  <td>
                    <span className={a.verified ? 'status status-up' : 'status status-down'}>
                      {a.verified ? 'verified' : 'failed'}
                    </span>
                    {!a.verified && a.failure_reason && (
                      <span className="field-hint"> {a.failure_reason}</span>
                    )}
                  </td>
                  <td>{a.method}</td>
                  <td>{a.signer_identity ? a.signer_identity : <NotProvided />}</td>
                  <td>{a.signer_issuer ? a.signer_issuer : <NotProvided />}</td>
                  <td>
                    {a.digest ? <code className="mono-sm">{a.digest}</code> : <NotProvided />}
                  </td>
                  <td title={`recorded by ${a.recorded_by}`}>{a.verified_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
