/**
 * AIBOM — the discovered AI model inventory, plus the four user-supplied
 * Table 10 elements no tool can ever report.
 *
 * ⚠ MOSTLY DISCOVERED, EDITABLE ONLY WHERE IT GENUINELY CANNOT BE. Sixteen
 * of Table 10's nineteen elements come from workers/aibom's discovery and
 * enrichment pipeline and are read-only here — editing them would silently
 * diverge from what the scan actually found. Only intended usage,
 * out-of-scope usage, security requirements and the attestation are ever
 * editable, because no tool can discover intent or policy
 * (services/project/internal/aibom's own package doc).
 */

import { useParams } from 'react-router';
import { useState } from 'react';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { useProject } from '../../lib/projects';
import {
  useAIModelForm,
  useAIModels,
  useUpdateAIModelUserFields,
  type AIModel,
  type AIModelUserFields,
} from '../../lib/aibom';

export function AIModelInventory() {
  const { id = '' } = useParams();
  const project = useProject(id);
  const { data, isPending, isError, error } = useAIModels(id);
  const form = useAIModelForm(id);

  if (isPending) return <SkeletonRows rows={6} columns={5} />;
  if (isError) return <ErrorState error={error} action="load the AI model inventory" />;

  const models = data?.ai_models ?? [];

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>AIBOM</h1>
          <p className="tagline">{project.data?.name ?? 'Project'}</p>
        </div>
      </header>

      {models.length === 0 ? (
        <EmptyState
          title="No AI models discovered yet"
          guidance="Run an AIBOM scan from Generate. ai-bom finds LLM providers, agent frameworks and model references in your code; aibom-generator enriches referenced models from their Hugging Face card."
        />
      ) : (
        <section className="panel" aria-labelledby="ai-models-heading">
          <h2 id="ai-models-heading">Models</h2>
          <div className="table-wrap">
            <table className="table">
              <caption className="table-caption">
                Risk Score and OWASP LLM Top-10 are AxeBOM extensions from Trusera ai-bom, not
                CERT-In Table 10 elements — excluded from coverage.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Model</th>
                  <th scope="col">Type</th>
                  <th scope="col">Developer</th>
                  <th scope="col">License</th>
                  <th scope="col">Datasets</th>
                  <th scope="col">Dependencies</th>
                  <th scope="col">Risk (extension)</th>
                  <th scope="col">OWASP Top-10 (extension)</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {models.map((m) => (
                  <ModelRow key={m.id} projectId={id} model={m} formFields={form.data?.fields} />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
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
  const [editing, setEditing] = useState(false);

  return (
    <>
      <tr>
        <td>{model.model_name}</td>
        <td>{model.model_type || '—'}</td>
        <td>{model.model_developer || '—'}</td>
        <td>{model.licensing || '—'}</td>
        <td title={model.datasets.map((d) => d.name).join(', ') || undefined}>
          {model.datasets.length}
        </td>
        <td title={model.dependencies.join(', ') || undefined}>{model.dependencies.length}</td>
        <td>{model.risk_score != null ? model.risk_score.toFixed(1) : '—'}</td>
        <td>{(model.owasp_llm_top10 ?? []).join(', ') || '—'}</td>
        <td>
          <button type="button" className="btn" onClick={() => setEditing((v) => !v)}>
            {editing ? 'Close' : 'Edit'}
          </button>
        </td>
      </tr>
      {editing && (
        <tr>
          <td colSpan={9}>
            <UserFieldsForm
              projectId={projectId}
              model={model}
              formFields={formFields}
              onDone={() => setEditing(false)}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function UserFieldsForm({
  projectId,
  model,
  formFields,
  onDone,
}: {
  projectId: string;
  model: AIModel;
  formFields: { field_id: string; canonical_path: string; name: string }[] | undefined;
  onDone: () => void;
}) {
  const update = useUpdateAIModelUserFields(projectId);
  const [values, setValues] = useState<AIModelUserFields>({
    security_requirements: orNotProvided(model.security_requirements),
    intended_usage: orNotProvided(model.intended_usage),
    out_of_scope_usage: orNotProvided(model.out_of_scope_usage),
    attestation_signature: orNotProvided(model.attestation_signature),
  });

  const fieldName = (key: keyof AIModelUserFields, fallback: string) =>
    formFields?.find((f) => canonicalKey(f.canonical_path) === key)?.name ?? fallback;

  return (
    <form
      className="panel"
      onSubmit={(e) => {
        e.preventDefault();
        update.mutate({ modelId: model.id, fields: values }, { onSuccess: onDone });
      }}
    >
      <p className="field-hint">
        No tool reports these four elements — they describe intent and policy, not anything
        discoverable from code or a model card. Anything left blank is recorded as{' '}
        <code>not-provided</code> and counts as a gap rather than being hidden.
      </p>
      <label className="field">
        <span>{fieldName('security_requirements', 'Security Requirements')}</span>
        <input
          type="text"
          value={values.security_requirements}
          onChange={(e) => setValues({ ...values, security_requirements: e.target.value })}
        />
      </label>
      <label className="field">
        <span>{fieldName('intended_usage', 'Intended Usage')}</span>
        <input
          type="text"
          value={values.intended_usage}
          onChange={(e) => setValues({ ...values, intended_usage: e.target.value })}
        />
      </label>
      <label className="field">
        <span>{fieldName('out_of_scope_usage', 'Out of Scope Usage')}</span>
        <input
          type="text"
          value={values.out_of_scope_usage}
          onChange={(e) => setValues({ ...values, out_of_scope_usage: e.target.value })}
        />
      </label>
      <label className="field">
        <span>{fieldName('attestation_signature', 'Attestations')}</span>
        <input
          type="text"
          value={values.attestation_signature}
          onChange={(e) => setValues({ ...values, attestation_signature: e.target.value })}
        />
      </label>
      <div className="step-actions">
        <button type="submit" className="btn btn-primary" disabled={update.isPending}>
          Save
        </button>
        <button type="button" className="btn" onClick={onDone}>
          Cancel
        </button>
      </div>
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
