/**
 * One device input, and the two groups they fall into.
 *
 * ⚠ EXTRACTED SO THERE IS ONE COPY. These render `DeviceFormField`, which the
 * server generates from `docs/reference/certin-v2.0.yaml` (CLAUDE.md invariant
 * 2) — so a guideline revision renames an input with no frontend release. Two
 * screens now draw this form: the device register on a project, and the
 * registration wizard for a project that does not exist yet. A second hand-
 * written copy would keep the profile's field list on one screen and a frozen
 * snapshot of it on the other, which is exactly the drift generating the form
 * was meant to prevent.
 */

import type { DeviceFormField, DeviceInput } from '../../lib/devices';

export function DeviceField({
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
 * DeviceFieldGroups renders the compliance elements and the asset-management
 * attributes as two labelled groups.
 *
 * ⚠ THE SPLIT IS THE POINT, NOT LAYOUT. The `certin` half scores against
 * coverage and the other half does not; putting an asset tag unlabelled beside
 * a CERT-In element implies that filling it in moves a compliance number. It
 * does not, and the second legend is what says so.
 *
 * ⚠ NO TABLE NUMBER AND NO COUNT IN THE COPY. `task profile:guardrails` caught
 * a literal "Table 11" in the original of this markup and was right to: the
 * guideline's own numbering goes stale exactly as a field count does, and
 * nothing fails when it happens. Each input carries its own page citation,
 * rendered from the profile.
 */
export function DeviceFieldGroups({
  fields,
  draft,
  onChange,
}: {
  fields: DeviceFormField[];
  draft: DeviceInput;
  onChange: (d: DeviceInput) => void;
}) {
  const set = (attr: string, value: string) => onChange({ ...draft, [attr]: value });
  const value = (attr: string) => (draft as unknown as Record<string, string>)[attr] ?? '';

  const certin = fields.filter((f) => f.certin);
  const ours = fields.filter((f) => !f.certin);

  return (
    <>
      <fieldset>
        <legend>CERT-In elements</legend>
        {/* These score. The group below does not, and saying so is the point. */}
        <div className="field-grid">
          {certin.map((f) => (
            <DeviceField key={f.attr} field={f} value={value(f.attr)} onChange={set} />
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
            <DeviceField key={f.attr} field={f} value={value(f.attr)} onChange={set} />
          ))}
        </div>
      </fieldset>
    </>
  );
}
