/**
 * The device register — what a project's hardware actually IS.
 *
 * ⚠ BEFORE THIS SCREEN THERE WAS NO WAY TO REGISTER HARDWARE AT ALL.
 *
 * A project had one anonymous parts tree. The level-0 row of that tree carried
 * a model and a serial, but a re-import replaced the whole document, so nothing
 * survived one; there was no uniqueness on serial, no way to address a single
 * device, and no way to hold two. A product line with three boards had nowhere
 * to put two of them.
 *
 * ⚠ REGISTRATION IS NOT DISCOVERY, AND THE COPY HERE HAS TO KEEP SAYING SO.
 * Every field on this screen is one a person types. AxeBOM does not reach a
 * device, and a form that implies otherwise is the claim CLAUDE.md's honest
 * labels forbid.
 */

import { useState } from 'react';

import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { useEngines } from '../../lib/engines';
import {
  EMPTY_DEVICE,
  describeParts,
  useCreateDevice,
  useDeleteDevice,
  useDevices,
  useUpdateDevice,
  type DeviceFormField,
  type DeviceInput,
  type HardwareDevice,
} from '../../lib/devices';

export function DeviceRegister({ projectId }: { projectId: string }) {
  const { data, isPending, isError, error, refetch } = useDevices(projectId);
  const create = useCreateDevice(projectId);
  const update = useUpdateDevice(projectId);
  const remove = useDeleteDevice(projectId);

  const [draft, setDraft] = useState<DeviceInput | null>(null);
  const [editing, setEditing] = useState<string | null>(null);

  if (isPending) return <SkeletonRows rows={3} columns={4} />;
  if (isError) {
    return (
      <ErrorState
        error={error}
        action="load this project's devices"
        onRetry={() => void refetch()}
      />
    );
  }

  const devices = data?.devices ?? [];
  const form = data?.form ?? [];

  function startNew() {
    setEditing(null);
    setDraft({ ...EMPTY_DEVICE });
  }

  function startEdit(d: HardwareDevice) {
    setEditing(d.id);
    setDraft({
      name: d.name,
      manufacturer: d.manufacturer,
      model_number: d.model_number,
      serial_number: d.serial_number,
      lot_number: d.lot_number,
      asset_tag: d.asset_tag,
      firmware_version: d.firmware_version,
      location: d.location,
      criticality: d.criticality,
      notes: d.notes,
    });
  }

  async function submit() {
    if (!draft) return;
    if (editing) {
      await update.mutateAsync({ id: editing, input: draft });
    } else {
      await create.mutateAsync(draft);
    }
    setDraft(null);
    setEditing(null);
  }

  const pending = create.isPending || update.isPending;
  const failure = create.error ?? update.error ?? remove.error;

  return (
    <section aria-labelledby="devices-heading">
      <div className="toolbar">
        <h2 id="devices-heading">Devices</h2>
        <span className="toolbar-spacer" />
        {!draft && (
          <button type="button" className="btn btn-primary" onClick={startNew}>
            Register a device
          </button>
        )}
      </div>

      {/* ⚠ STATED ONCE, AT THE TOP, WHERE THE DECISION IS MADE. */}
      <p className="field-hint">
        A device is something you have — a board, an appliance, a shipped unit. Register it here,
        then attach its parts by importing a file, uploading what a collector on that machine
        reported, or entering them by hand. <strong>AxeBOM never reaches the device</strong>;
        everything below is what you tell it.
      </p>

      {failure && <ErrorState error={failure} action="save this device" />}

      {draft && (
        <DeviceForm
          fields={form}
          draft={draft}
          editing={editing !== null}
          pending={pending}
          onChange={setDraft}
          onCancel={() => {
            setDraft(null);
            setEditing(null);
          }}
          onSubmit={() => void submit()}
        />
      )}

      {devices.length === 0 && !draft && (
        <EmptyState
          title="No device registered yet"
          guidance={
            'Nothing here examined physical hardware, and nothing can. A hardware BOM starts ' +
            'from a device you tell AxeBOM about — then its parts come from your design files, ' +
            'a parts list, or a report the machine itself produced.'
          }
          action={
            <button type="button" className="btn btn-primary" onClick={startNew}>
              Register a device
            </button>
          }
        />
      )}

      <CollectorInstructions />

      {devices.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Device</th>
                <th>Model</th>
                <th>Serial / asset tag</th>
                <th>Parts</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td>
                    <strong>{d.name}</strong>
                    {d.manufacturer && <div className="cell-sub">{d.manufacturer}</div>}
                  </td>
                  <td>{d.model_number || <NotRecorded />}</td>
                  <td>
                    {d.serial_number || d.asset_tag ? (
                      <>
                        {d.serial_number && <div>{d.serial_number}</div>}
                        {d.asset_tag && <div className="cell-sub">{d.asset_tag}</div>}
                      </>
                    ) : (
                      <NotRecorded />
                    )}
                  </td>
                  <td>{describeParts(d)}</td>
                  <td className="num">
                    <button type="button" className="btn btn-sm" onClick={() => startEdit(d)}>
                      Edit
                    </button>{' '}
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={remove.isPending}
                      onClick={() => void remove.mutateAsync(d.id)}
                    >
                      Retire
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * NotRecorded is deliberately quieter than `not-provided`.
 *
 * A blank serial on a prototype is an ordinary state, not a compliance gap —
 * unlike a missing CERT-In element on a component, which the report scores.
 */
function NotRecorded() {
  return <span className="not-provided">not recorded</span>;
}

/**
 * DeviceForm renders inputs from the server's field list.
 *
 * ⚠ NOT A HARDCODED SET OF <input>s. The names and CERT-In element ids come
 * from the compliance profile, so a guideline revision changes a label without
 * a frontend release (invariant 2) — the same mechanism the QBOM device form
 * already uses.
 */
function DeviceForm({
  fields,
  draft,
  editing,
  pending,
  onChange,
  onCancel,
  onSubmit,
}: {
  fields: DeviceFormField[];
  draft: DeviceInput;
  editing: boolean;
  pending: boolean;
  onChange: (d: DeviceInput) => void;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const set = (attr: string, value: string) => onChange({ ...draft, [attr]: value });
  const value = (attr: string) => (draft as unknown as Record<string, string>)[attr] ?? '';

  const certin = fields.filter((f) => f.certin);
  const ours = fields.filter((f) => !f.certin);

  return (
    <form
      className="panel"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <fieldset>
        {/* ⚠ NO TABLE NUMBER AND NO COUNT. `task profile:guardrails` caught
            "Table 11" here — 11 is also the QBOM element count — and it was
            right to: a literal reference to the guideline's own numbering goes
            stale exactly as a field count does, and nothing fails when it
            happens. Each input carries its own page citation, rendered from the
            profile, which is both more precise and self-updating. */}
        <legend>CERT-In elements</legend>
        {/* These score. The group below does not, and saying so is the point. */}
        <div className="field-grid">
          {certin.map((f) => (
            <Field key={f.attr} field={f} value={value(f.attr)} onChange={set} />
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend>Asset management</legend>
        <p className="field-hint">
          AxeBOM additions, not CERT-In elements. They help you find a device again; they do not
          move any coverage number.
        </p>
        <div className="field-grid">
          {ours.map((f) => (
            <Field key={f.attr} field={f} value={value(f.attr)} onChange={set} />
          ))}
        </div>
      </fieldset>

      <div className="panel-actions">
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="btn btn-primary" disabled={pending || !draft.name.trim()}>
          {pending ? 'Saving…' : editing ? 'Save changes' : 'Register device'}
        </button>
      </div>
    </form>
  );
}

function Field({
  field,
  value,
  onChange,
}: {
  field: DeviceFormField;
  value: string;
  onChange: (attr: string, value: string) => void;
}) {
  if (field.values) {
    return (
      <label className="field">
        <span>
          {field.name}
          {field.required && ' *'}
        </span>
        <select value={value} onChange={(e) => onChange(field.attr, e.target.value)}>
          <option value="">—</option>
          {field.values.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        {field.source_page ? <small>CERT-In p.{field.source_page}</small> : null}
      </label>
    );
  }

  return (
    <label className="field">
      <span>
        {field.name}
        {field.required && ' *'}
      </span>
      {field.multiline ? (
        <textarea
          rows={3}
          value={value}
          required={field.required}
          onChange={(e) => onChange(field.attr, e.target.value)}
        />
      ) : (
        <input
          value={value}
          required={field.required}
          onChange={(e) => onChange(field.attr, e.target.value)}
        />
      )}
      {field.source_page ? <small>CERT-In p.{field.source_page}</small> : null}
    </label>
  );
}

/**
 * CollectorInstructions tells somebody how to get parts off a device.
 *
 * ⚠ NOTHING IN THE PRODUCT SAID THIS. `hbom-cdxgen-host` and
 * `hbom-host-report` parse a report the customer generates on the machine they
 * want documented — and the only written explanation was in
 * OSINT/tools.manifest.yaml, which no browser reads, plus an adapter hint that
 * appears AFTER a scan has already run and found nothing. A customer could not
 * discover the feature, let alone use it.
 *
 * Rendered from the engine registry rather than written here, so an engine that
 * gains or loses an operator action changes this panel without a frontend
 * release — and so the instruction cannot drift from the engine that needs it.
 */
function CollectorInstructions() {
  const { engines } = useEngines(undefined, 'HBOM');
  const withAction = (engines ?? []).filter((e) => e.operator_action);

  if (withAction.length === 0) return null;

  return (
    <details className="panel">
      <summary>
        <strong>Getting parts off a device you have</strong>
      </summary>
      <p className="field-hint">
        AxeBOM cannot reach your device, so these are things you run yourself and upload. Attach the
        result to this project as an upload, then run a scan.
      </p>
      <dl className="meta">
        {withAction.map((e) => (
          <div key={e.engine_id}>
            <dt>{e.engine_id}</dt>
            <dd>{e.operator_action}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
