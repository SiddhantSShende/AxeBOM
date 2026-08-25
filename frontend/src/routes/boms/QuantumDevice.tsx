/**
 * QBOM — quantum readiness (derived from CBOM) plus the Table 8 device form.
 *
 * ⚠ TWO THINGS JOINED, NEVER CONFLATED — workers/qbom/derive.py's own
 * warning. The readiness view is a REFERENCE into this project's CBOM
 * crypto assets, regrouped by the four buckets `quantum_readiness_group`
 * already carries; nothing here re-derives a verdict. The device form below
 * it is the nine free-form Table 8 elements a human supplies — there is no
 * quantum-hardware scanner, and the disclosure text below says so in the
 * API's own words, not a copy that can drift from it.
 */

import { useParams } from 'react-router';
import { useState } from 'react';
import { ErrorState, SkeletonRows } from '../../components/States';
import { useProject } from '../../lib/projects';
import { readinessLabel, useCryptoAssets, type CryptoAsset } from '../../lib/crypto';
import {
  useQBOMForm,
  useQuantumDevice,
  useSaveQuantumDevice,
  type QuantumDeviceValues,
} from '../../lib/qbom';

const READINESS_ORDER: NonNullable<CryptoAsset['quantum_readiness_group']>[] = [
  'vulnerable',
  'grover_note',
  'post_quantum',
  'unassessed',
];

export function QuantumDevice() {
  const { id = '' } = useParams();
  const project = useProject(id);
  const cryptoAssets = useCryptoAssets(id);

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>QBOM</h1>
          <p className="tagline">{project.data?.name ?? 'Project'}</p>
        </div>
      </header>

      <section className="panel" aria-labelledby="readiness-heading">
        <h2 id="readiness-heading">Quantum readiness</h2>
        {cryptoAssets.isPending && <SkeletonRows rows={4} columns={2} />}
        {cryptoAssets.isError && (
          <ErrorState error={cryptoAssets.error} action="load quantum readiness" />
        )}
        {cryptoAssets.data && (
          <ReadinessSummary assets={cryptoAssets.data.crypto_assets} />
        )}
      </section>

      <DeviceForm projectId={id} />
    </div>
  );
}

function ReadinessSummary({ assets }: { assets: CryptoAsset[] }) {
  if (assets.length === 0) {
    return (
      <p className="field-hint">
        No cryptographic assets were discovered, so nothing could be assessed for quantum
        vulnerability. That is not the same as having no quantum-vulnerable cryptography —
        check the CBOM Engine Coverage panel for whether a CBOM engine has run at all.
      </p>
    );
  }

  const groups = new Map<string, CryptoAsset[]>();
  for (const a of assets) {
    const key = a.quantum_readiness_group ?? 'unclassified';
    groups.set(key, [...(groups.get(key) ?? []), a]);
  }

  return (
    <dl className="meta">
      {READINESS_ORDER.map((group) => {
        const rows = groups.get(group) ?? [];
        if (rows.length === 0) return null;
        return (
          <div key={group}>
            <dt>{readinessLabel(group)}</dt>
            <dd>
              {rows.length} asset{rows.length === 1 ? '' : 's'} — {rows.map((r) => r.name).join(', ')}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

function DeviceForm({ projectId }: { projectId: string }) {
  const form = useQBOMForm(projectId);
  const device = useQuantumDevice(projectId);
  const save = useSaveQuantumDevice(projectId);

  const [draft, setDraft] = useState<QuantumDeviceValues | null>(null);

  if (form.isPending || device.isPending) return <SkeletonRows rows={6} columns={1} />;
  if (form.isError) return <ErrorState error={form.error} action="load the QBOM form" />;
  if (device.isError) return <ErrorState error={device.error} action="load device metadata" />;

  const values: QuantumDeviceValues = draft ?? {
    model_name: device.data?.model_name ?? '',
    version: device.data?.version ?? '',
    vendor_origin: device.data?.vendor_origin ?? '',
    license_info: device.data?.license_info ?? '',
    communication_protocol: device.data?.communication_protocol ?? '',
    hardware: device.data?.hardware ?? '',
    software_dependencies: device.data?.software_dependencies ?? [],
    environmental_impact: device.data?.environmental_impact ?? '',
    attestation_signature: device.data?.attestation_signature ?? '',
  };

  const set = <K extends keyof QuantumDeviceValues>(key: K, value: QuantumDeviceValues[K]) =>
    setDraft({ ...values, [key]: value });

  const freeFormFields = (form.data?.fields ?? []).filter((f) => !f.derived);

  return (
    <section className="panel" aria-labelledby="device-heading">
      <h2 id="device-heading">Device metadata</h2>
      <p className="field-hint">{form.data?.disclosure}</p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(values, { onSuccess: () => setDraft(null) });
        }}
      >
        {freeFormFields.map((f) => {
          const key = fieldKey(f.canonical_path);
          // ⚠ THE ONLY LIST-TYPED ELEMENT. Every other Table 8 free-form
          // field is a plain string; branching on the one known key avoids
          // an `any`-typed dynamic lookup into QuantumDeviceValues for what
          // is otherwise a fully statically-known shape.
          if (key === 'software_dependencies') {
            return (
              <label key={f.field_id} className="field">
                <span>{f.name}</span>
                <input
                  type="text"
                  value={values.software_dependencies.join(', ')}
                  placeholder="comma-separated"
                  onChange={(e) =>
                    set(
                      'software_dependencies',
                      e.target.value
                        .split(',')
                        .map((s) => s.trim())
                        .filter(Boolean),
                    )
                  }
                />
              </label>
            );
          }
          return (
            <label key={f.field_id} className="field">
              <span>{f.name}</span>
              <input
                type="text"
                value={stringField(values, key)}
                onChange={(e) => setStringField(set, key, e.target.value)}
              />
            </label>
          );
        })}

        <div className="step-actions">
          <button type="submit" className="btn btn-primary" disabled={save.isPending}>
            Save
          </button>
        </div>
        {save.isError && <p className="status status-down">{save.error.message}</p>}
      </form>

      {device.data && device.data.gaps.length > 0 && (
        <div className="field-hint">
          {/* ⚠ RENDERED FROM THE PROFILE, NEVER THE LITERAL 11. CLAUDE.md
              invariant 2 — a CERT-In revision changes form.data.fields.length
              on its own; a hardcoded count would silently stop matching it. */}
          <strong>{device.data.gaps.length}</strong> of {form.data?.fields.length ?? '?'}{' '}
          elements not recorded:
          <ul>
            {device.data.gaps.map((g) => (
              <li key={g.field_id}>
                {g.name} — {g.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function fieldKey(canonicalPath: string): string {
  return canonicalPath.replace(/^quantum_component\./, '').replace(/\[\]$/, '');
}

/** The string-typed keys of QuantumDeviceValues — every key except the one
 * list field, `software_dependencies`, which is handled separately above. */
type StringFieldKey = Exclude<keyof QuantumDeviceValues, 'software_dependencies'>;

function isStringFieldKey(key: string): key is StringFieldKey {
  return key !== 'software_dependencies';
}

/** Reads one of the nine free-form string fields by its canonical-path-derived
 * key, narrowed against the profile's own field list rather than cast. */
function stringField(values: QuantumDeviceValues, key: string): string {
  return isStringFieldKey(key) ? values[key] : '';
}

function setStringField(
  set: <K extends keyof QuantumDeviceValues>(key: K, value: QuantumDeviceValues[K]) => void,
  key: string,
  value: string,
): void {
  if (isStringFieldKey(key)) set(key, value);
}
