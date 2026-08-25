/**
 * Engine settings — configurable tool management.
 *
 * ⚠ THE FIRST AXEBOM-NATIVE ADMIN SETTINGS SCREEN. Every other "settings"
 * page either reads state nothing edits (SettingsIndex's org panel) or is
 * scoped to one project. This one changes what every future scan in this
 * tenant executes, which is why it is gated on
 * `ResourceEngine:configure_engines` (Admin), not the generic project-edit
 * permission — mirrors how enabling package-manager resolution gets its own
 * matrix row rather than piggybacking on `update`.
 *
 * ⚠ VIEWABLE BY ANYONE, EDITABLE ONLY BY AN ADMIN. `GET
 * /v1/scans/engine-policy` is Viewer-gated; only the write is Admin-gated.
 * Hiding the whole page from non-admins would hide the answer to "why did
 * this scan only run two engines" from the one person most likely to be
 * asking. `useRole` only hides the CONTROLS — the server is the actual gate,
 * per its own warning.
 */

import { useState } from 'react';
import { BOM_TYPES, bomMeta, type BomType } from '../../design/theme';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { useRole } from '../../lib/useAuth';
import {
  useEnginePolicies,
  useEngines,
  useResetEnginePolicy,
  useUpsertEnginePolicy,
  type EngineInfo,
  type EnginePolicy,
} from '../../lib/engines';

export function Engines() {
  const { atLeast } = useRole();
  const canEdit = atLeast('admin');
  const policies = useEnginePolicies();

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Engines</h1>
          <p className="tagline">
            Which OSINT engines run for each BOM type, tenant-wide. An absent override means the
            built-in default set.
          </p>
        </div>
      </header>

      {!canEdit && (
        <p className="field-hint">
          Viewing only — changing which engines run requires the Admin role. Ask an admin in your
          organisation to make changes here.
        </p>
      )}

      {policies.isError && <ErrorState error={policies.error} action="load engine settings" />}

      {BOM_TYPES.map((b) => (
        <EnginePolicyCard
          key={b.type}
          family={b.type}
          canEdit={canEdit}
          current={policies.data?.engine_policies.find(
            (p) => p.family.toUpperCase() === b.type,
          )}
        />
      ))}
    </div>
  );
}

function EnginePolicyCard({
  family,
  canEdit,
  current,
}: {
  family: BomType;
  canEdit: boolean;
  current: EnginePolicy | undefined;
}) {
  const meta = bomMeta(family);
  const { engines, isPending, isError, error } = useEngines(undefined, family);
  const upsert = useUpsertEnginePolicy();
  const reset = useResetEnginePolicy();

  // ⚠ SEEDED FROM THE CURRENT OVERRIDE, OR FROM EVERY REGISTRY ENGINE WHEN
  // THERE IS NONE — that second case IS the built-in default's engine_ids,
  // so a first-time editor sees what is actually running today, not a blank
  // form they might mistake for "nothing runs".
  const defaultIDs = (engines ?? []).map((e) => e.engine_id);
  const [selected, setSelected] = useState<string[] | null>(null);
  const [enabled, setEnabled] = useState<boolean | null>(null);

  const engineIDs = selected ?? current?.engine_ids ?? defaultIDs;
  const isEnabled = enabled ?? current?.enabled ?? true;
  const dirty = selected !== null || enabled !== null;

  const toggleEngine = (id: string) => {
    const base = selected ?? current?.engine_ids ?? defaultIDs;
    setSelected(base.includes(id) ? base.filter((x) => x !== id) : [...base, id]);
  };

  const save = () => {
    upsert.mutate(
      { family, engine_ids: engineIDs, enabled: isEnabled },
      {
        onSuccess: () => {
          setSelected(null);
          setEnabled(null);
        },
      },
    );
  };

  const revert = () => {
    reset.mutate(family, {
      onSuccess: () => {
        setSelected(null);
        setEnabled(null);
      },
    });
  };

  return (
    <section className="card" aria-labelledby={`engine-policy-${meta.token}`}>
      <h2 id={`engine-policy-${meta.token}`} data-bom={meta.token}>
        <span aria-hidden="true">{meta.glyph}</span> {meta.label}
      </h2>
      <p className="step-hint">{meta.summary}</p>

      {current ? (
        <p className="field-hint">
          Customised{current.note ? ` — ${current.note}` : ''}.{' '}
          {current.enabled ? '' : 'Currently disabled: no engine runs for this BOM type.'}
        </p>
      ) : (
        <p className="field-hint">Using the built-in default set.</p>
      )}

      {isPending && <SkeletonRows rows={2} columns={1} />}
      {isError && <ErrorState error={error} action="load engines for this BOM type" />}
      {!isPending && !isError && (engines ?? []).length === 0 && (
        <EmptyState title="No engines registered" guidance="This BOM type has no engines in the registry." />
      )}

      {!isPending && (engines ?? []).length > 0 && (
        <>
          <ul className="chips chips-selectable">
            {(engines ?? []).map((e) => (
              <EngineOption
                key={e.engine_id}
                engine={e}
                checked={engineIDs.includes(e.engine_id)}
                disabled={!canEdit}
                onToggle={() => toggleEngine(e.engine_id)}
              />
            ))}
          </ul>

          {canEdit && (
            <>
              <label className="field-inline">
                <input
                  type="checkbox"
                  checked={isEnabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
                <span>Run this BOM type at all</span>
              </label>

              <div className="step-actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={save}
                  disabled={!dirty || upsert.isPending}
                >
                  Save
                </button>
                {current && (
                  <button
                    type="button"
                    className="btn btn-quiet"
                    onClick={revert}
                    disabled={reset.isPending}
                  >
                    Revert to default
                  </button>
                )}
              </div>
              {upsert.isError && <p className="status status-down">{upsert.error.message}</p>}
            </>
          )}
        </>
      )}
    </section>
  );
}

function EngineOption({
  engine,
  checked,
  disabled,
  onToggle,
}: {
  engine: EngineInfo;
  checked: boolean;
  disabled: boolean;
  onToggle: () => void;
}) {
  return (
    <li>
      <label className="chip" data-selected={checked}>
        <input type="checkbox" checked={checked} disabled={disabled} onChange={onToggle} />
        <span>{engine.engine_id}</span>
        {engine.requires_import && <span className="chip-note">import only</span>}
        {engine.is_derived && <span className="chip-note">derived</span>}
      </label>
    </li>
  );
}
