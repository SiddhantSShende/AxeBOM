/**
 * AIBOM — the discovered AI inventory, and the elements no tool can report.
 *
 * ⚠ MOSTLY DISCOVERED, EDITABLE ONLY WHERE IT GENUINELY CANNOT BE DISCOVERED.
 * Nearly all of CERT-In Table 10 comes from workers/aibom's discovery and
 * enrichment pipeline and is read-only here — editing it would silently diverge
 * from what the scan actually found. The editable set is exactly what the
 * compliance profile marks `user_supplied`, and the SERVER renders that set
 * (`GET /v1/aibom/{id}/form`). This file must never name the elements or say how
 * many there are: a count written here is a false compliance claim the day the
 * guideline is revised (CLAUDE.md invariant 2).
 *
 * ⚠ PARSED AND DISCOVERED. NEVER EVALUATED. An engine read a model reference out
 * of source, or read a publisher's own model card. Nothing here tested a model,
 * measured its bias, audited its licence or ran it.
 * `frontend/src/lib/aibom.claims.test.ts` holds this file to that.
 */

import { useParams, useSearchParams } from 'react-router';
import { useState } from 'react';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { NotProvided, ProvenanceChips, Value } from '../../components/Chips';
import {
  useAIModelForm,
  useAIModels,
  useUpdateAIModelUserFields,
  type AIModel,
  type AIModelUserFields,
} from '../../lib/aibom';
import { AIAssets } from './AIAssets';
import { AIDatasets } from './AIDatasets';
import { AIGovernance } from './AIGovernance';

/** The sub-screens, in the order a reader works through them: what was found,
 *  what it was trained on, what surrounds it, and what a person declared. */
const VIEWS = [
  { id: 'models', label: 'Models' },
  { id: 'datasets', label: 'Datasets' },
  { id: 'assets', label: 'AI assets' },
  { id: 'governance', label: 'Governance' },
] as const;

type ViewId = (typeof VIEWS)[number]['id'];

export function AIModelInventory() {
  const { id = '' } = useParams();
  // ⚠ IN THE URL, NOT IN STATE. A reviewer sharing "the assets we found" sends a
  // link, and a reload lands back where they were rather than on Models.
  const [params, setParams] = useSearchParams();
  const requested = params.get('view');
  const view: ViewId = VIEWS.some((v) => v.id === requested) ? (requested as ViewId) : 'models';

  const { data, isPending, isError, error } = useAIModels(id);
  const form = useAIModelForm(id);

  if (isPending) return <SkeletonRows rows={6} columns={5} />;
  if (isError) return <ErrorState error={error} action="load the AI model inventory" />;

  const models = data?.ai_models ?? [];
  const assets = data?.ai_assets ?? [];
  const nothingFound = models.length === 0 && assets.length === 0;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>AIBOM</h1>
          {/* The project name is carried by the crumb above the tabs (App.tsx's
              ProjectCrumb); repeating it here printed it twice in one header. */}
        </div>
      </header>

      {nothingFound ? (
        <EmptyState
          title="No AI models or assets discovered yet"
          guidance="Run an AIBOM scan from Generate. ai-bom, airom and cdxgen-ai read model references, prompts, vector stores and RAG pipelines out of your source; the enrichment worker then asks each referenced model's own card about itself."
        />
      ) : (
        <>
          <nav className="subtabs" aria-label="AIBOM sections">
            {VIEWS.map((v) => (
              <button
                key={v.id}
                type="button"
                className="subtab"
                aria-current={view === v.id ? 'page' : undefined}
                onClick={() => setParams(v.id === 'models' ? {} : { view: v.id })}
              >
                {v.label}
                {v.id === 'models' && models.length > 0 && (
                  <span className="subtab-count">{models.length}</span>
                )}
                {v.id === 'assets' && assets.length > 0 && (
                  <span className="subtab-count">{assets.length}</span>
                )}
              </button>
            ))}
          </nav>

          {view === 'models' && (
            <ModelsPanel projectId={id} models={models} formFields={form.data?.fields} />
          )}
          {view === 'datasets' && <AIDatasets models={models} />}
          {view === 'assets' && <AIAssets assets={assets} />}
          {view === 'governance' && <AIGovernance projectId={id} models={models} />}
        </>
      )}
    </div>
  );
}

/** The models table's columns. Data rather than markup so the detail row's
 *  `colSpan` is DERIVED from them — written twice, the two drift the first time
 *  a column is added and the table visibly breaks. The last is the actions
 *  column and has no heading. */
const MODEL_COLUMNS = [
  'Model',
  'Identity',
  'Found by',
  'Where',
  'Type',
  'Developer',
  'License',
  'Datasets',
  'Dependencies',
  'Risk (extension)',
  'OWASP Top-10 (extension)',
  '',
] as const;

function ModelsPanel({
  projectId,
  models,
  formFields,
}: {
  projectId: string;
  models: AIModel[];
  formFields: { field_id: string; canonical_path: string; name: string }[] | undefined;
}) {
  if (models.length === 0) {
    return (
      <EmptyState
        title="No AI models discovered"
        guidance="Assets were found but no model reference was. A repository can genuinely have prompts and a vector store without naming a model in code — the model may be configured at deploy time, which no source scan can see."
      />
    );
  }

  return (
    <section className="panel" aria-labelledby="ai-models-heading">
      <h2 id="ai-models-heading">Models</h2>
      <div className="table-wrap">
        <table className="table">
          <caption className="table-caption">
            Risk Score and OWASP LLM Top-10 are AxeBOM extensions from Trusera ai-bom, not CERT-In
            Table 10 elements — excluded from coverage.
          </caption>
          <thead>
            <tr>
              {MODEL_COLUMNS.map((label, i) =>
                label === '' ? (
                  // The actions column, deliberately unlabelled.
                  <th scope="col" key={`actions-${i}`} />
                ) : (
                  <th scope="col" key={label}>
                    {label}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {models.map((m) => (
              <ModelRow key={m.id} projectId={projectId} model={m} formFields={formFields} />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ModelRow({
  projectId,
  model,
  formFields,
}: {
  projectId: string;
  model: AIModel;
  formFields: { field_id: string; canonical_path: string; name: string }[] | undefined;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <tr>
        <td>
          {model.model_name}
          <VerifiedMark model={model} />
        </td>
        <td>
          <IdentityCell model={model} />
        </td>
        <td>
          <ProvenanceChips engines={model.found_by} />
        </td>
        <td>
          <EvidenceCell lines={model.evidence} />
        </td>
        <td>
          <Value>{model.model_type}</Value>
        </td>
        <td>
          <Value>{model.model_developer}</Value>
        </td>
        <td>
          <Value>{model.licensing}</Value>
        </td>
        <td title={model.datasets.map((d) => d.name).join(', ') || undefined}>
          {model.datasets.length}
        </td>
        <td title={model.dependencies.slice(0, 40).join(', ') || undefined}>
          {model.dependencies.length}
        </td>
        <td>{model.risk_score != null ? model.risk_score.toFixed(1) : <NotProvided />}</td>
        <td>
          {model.owasp_llm_top10?.length ? model.owasp_llm_top10.join(', ') : <NotProvided />}
        </td>
        <td>
          <button type="button" className="btn" onClick={() => setOpen((v) => !v)}>
            {open ? 'Close' : 'Details'}
          </button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={MODEL_COLUMNS.length}>
            <ModelDetail projectId={projectId} model={model} formFields={formFields} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * VerifiedMark says whether an engine confirmed this model exists upstream.
 *
 * ⚠ UNVERIFIED IS NOT A FAILURE, AND THE WORDING HAS TO CARRY THAT. Almost
 * every model here is unverified today, because confirming one means reaching
 * Hugging Face and the scan sandbox has no network. A red cross beside three
 * correctly-identified models would make a reader distrust data that is right.
 */
function VerifiedMark({ model }: { model: AIModel }) {
  if (!model.verified) {
    return (
      <span
        className="verify-mark verify-unconfirmed"
        title="Not confirmed upstream. The model was found in your source; no engine has resolved it against the publisher yet. This is not a sign that it is wrong."
      >
        unconfirmed
      </span>
    );
  }
  return (
    <span
      className="verify-mark verify-ok"
      title="An engine resolved this model against its publisher and it exists."
    >
      confirmed
    </span>
  );
}

/**
 * IdentityCell shows the merge key and how it was derived.
 *
 * ⚠ THE RULE AND THE CONFIDENCE ARE THE POINT, NOT DECORATION. `hf_repo` and
 * `name` are not the same claim: the first resolves to one repository on the
 * hub, the second is a string somebody typed. Two rows that look equally
 * confident but merged under different rules is how one model becomes three,
 * which is the defect this whole vertical was rebuilt to fix
 * (03-NORMALIZER-SPEC §1.5).
 */
function IdentityCell({ model }: { model: AIModel }) {
  if (!model.model_key) return <NotProvided />;
  return (
    <span className="identity" title={model.model_key}>
      <code className="mono-sm">{model.model_key}</code>
      {model.identity_rule && (
        <span className="identity-rule" data-confidence={model.identity_confidence}>
          {model.identity_rule}
          {model.identity_confidence ? ` · ${model.identity_confidence}` : ''}
        </span>
      )}
    </span>
  );
}

/** EvidenceCell shows where an engine saw the reference, as `path:line`. */
function EvidenceCell({ lines }: { lines: string[] }) {
  if (lines.length === 0) return <NotProvided />;
  const [first, ...rest] = lines;
  return (
    <span title={lines.join('\n')}>
      <code className="mono-sm">{first}</code>
      {rest.length > 0 && <span className="evidence-more"> +{rest.length}</span>}
    </span>
  );
}

/** ModelDetail is everything that does not fit a row: the full evidence list,
 *  the dependency list, this model's own datasets, and the editable elements. */
function ModelDetail({
  projectId,
  model,
  formFields,
}: {
  projectId: string;
  model: AIModel;
  formFields: { field_id: string; canonical_path: string; name: string }[] | undefined;
}) {
  return (
    <div className="model-detail">
      <div className="model-detail-cols">
        <div>
          <h4>Where it was referenced</h4>
          {model.evidence.length === 0 ? (
            <p className="field-hint">
              No engine reported a location. The model is recorded; where it is used is not known.
            </p>
          ) : (
            <ul className="plain-list">
              {model.evidence.map((e) => (
                <li key={e}>
                  <code className="mono-sm">{e}</code>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h4>Datasets ({model.datasets.length})</h4>
          {model.datasets.length === 0 ? (
            <p className="field-hint">
              This model&apos;s card named none. Nothing inspects training data.
            </p>
          ) : (
            <ul className="plain-list">
              {model.datasets.map((d) => (
                <li key={d.name}>
                  {d.name}
                  {d.license ? ` — ${d.license}` : ''}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h4>Dependencies ({model.dependencies.length})</h4>
          {model.dependencies.length === 0 ? (
            <p className="field-hint">No AI framework or library was linked to this model.</p>
          ) : (
            <ul className="plain-list scroll-list">
              {model.dependencies.map((d) => (
                <li key={d}>
                  <code className="mono-sm">{d}</code>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <UserFieldsForm projectId={projectId} model={model} formFields={formFields} />
    </div>
  );
}

function UserFieldsForm({
  projectId,
  model,
  formFields,
}: {
  projectId: string;
  model: AIModel;
  formFields: { field_id: string; canonical_path: string; name: string }[] | undefined;
}) {
  const update = useUpdateAIModelUserFields(projectId);
  const [values, setValues] = useState<AIModelUserFields>({
    security_requirements: orNotProvided(model.security_requirements),
    intended_usage: orNotProvided(model.intended_usage),
    out_of_scope_usage: orNotProvided(model.out_of_scope_usage),
    environmental_impact: orNotProvided(model.environmental_impact),
    attestation_signature: orNotProvided(model.attestation_signature),
  });
  const [saved, setSaved] = useState(false);

  const fieldName = (key: keyof AIModelUserFields, fallback: string) =>
    formFields?.find((f) => canonicalKey(f.canonical_path) === key)?.name ?? fallback;

  const field = (key: keyof AIModelUserFields, fallback: string, rows = 1) => (
    <label className="field">
      <span>{fieldName(key, fallback)}</span>
      {rows > 1 ? (
        <textarea
          rows={rows}
          value={values[key]}
          onChange={(e) => setValues({ ...values, [key]: e.target.value })}
        />
      ) : (
        <input
          type="text"
          value={values[key]}
          onChange={(e) => setValues({ ...values, [key]: e.target.value })}
        />
      )}
    </label>
  );

  return (
    <form
      className="panel"
      onSubmit={(e) => {
        e.preventDefault();
        setSaved(false);
        update.mutate(
          { modelKey: model.model_key, fields: values },
          { onSuccess: () => setSaved(true) },
        );
      }}
    >
      <h4>What no tool can report</h4>
      <p className="field-hint">
        These describe intent and policy, not anything discoverable from code or a model card, so
        the profile marks them for you to supply. Anything left blank is recorded as{' '}
        <code>not-provided</code> and counts as a gap rather than being hidden.
      </p>
      {field('security_requirements', 'Security Requirements')}
      {field('intended_usage', 'Intended Usage')}
      {field('out_of_scope_usage', 'Out of Scope Usage')}
      {field('environmental_impact', 'Environmental Impact', 2)}
      {field('attestation_signature', 'Attestations')}
      <div className="step-actions">
        <button type="submit" className="btn btn-primary" disabled={update.isPending}>
          Save
        </button>
      </div>
      {saved && !update.isPending && (
        <p className="status status-up" role="status">
          Saved against <code className="mono-sm">{model.model_key}</code>, so it survives the next
          scan.
        </p>
      )}
      {update.isError && <p className="status status-down">{update.error.message}</p>}
    </form>
  );
}

function orNotProvided(value: string | undefined): string {
  return value && value !== 'not-provided' ? value : '';
}

function canonicalKey(canonicalPath: string): string {
  return canonicalPath.replace(/^ai_model\./, '');
}
