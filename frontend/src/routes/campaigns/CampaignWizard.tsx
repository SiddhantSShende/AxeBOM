/**
 * The schedule wizard.
 *
 * ⚠ THE CRON EXPRESSION IS ALWAYS VISIBLE AND ALWAYS EDITABLE.
 *
 * Presets cover what most people want. But a preset-only UI is a trap: the
 * moment somebody needs "weekdays at 6am" they find the product cannot say it,
 * and a schedule nobody can read is a schedule nobody can audit — which for a
 * compliance product is the whole value. So the presets WRITE the expression,
 * the expression is shown, and typing in it is a supported path rather than an
 * escape hatch hidden behind "advanced".
 */

import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { ErrorState } from '../../components/States';
import {
  SCHEDULE_PRESETS,
  browserTimezone,
  describeCron,
  matchPreset,
  useCreateCampaign,
  validateCron,
} from '../../lib/campaigns';
import { useProjects } from '../../lib/projects';
import { BOM_TYPES } from '../../design/theme';

const REPORT_LEVELS = ['top_level', 'complete'] as const;
const STANDARDS = ['spdx', 'cyclonedx'] as const;
const FORMATS = ['pdf', 'xlsx', 'json'] as const;

export function CampaignWizard() {
  const navigate = useNavigate();
  const create = useCreateCampaign();
  const projectsQuery = useProjects();
  const projects = projectsQuery.data?.projects ?? [];

  const [name, setName] = useState('');
  const [cron, setCron] = useState(SCHEDULE_PRESETS[0]?.cron ?? '30 2 * * *');
  const [timezone, setTimezone] = useState(browserTimezone());
  const [projectIds, setProjectIds] = useState<string[]>([]);
  const [bomTypes, setBomTypes] = useState<string[]>(['sbom']);
  const [levels, setLevels] = useState<string[]>(['top_level']);
  const [standards, setStandards] = useState<string[]>(['spdx']);
  const [formats, setFormats] = useState<string[]>(['pdf']);

  const cronError = validateCron(cron);
  const activePreset = matchPreset(cron);

  const problems: string[] = [];
  if (name.trim() === '') problems.push('Give the campaign a name.');
  if (projectIds.length === 0) problems.push('Choose at least one project.');
  if (bomTypes.length === 0) problems.push('Choose at least one BOM type.');
  if (formats.length === 0) problems.push('Choose at least one report format.');
  if (cronError) problems.push(cronError);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (problems.length > 0) return;

    create.mutate(
      {
        name: name.trim(),
        project_ids: projectIds,
        cron_expr: cron.trim(),
        timezone,
        bom_types: bomTypes,
        report_levels: levels,
        standards,
        formats,
        enabled: true,
      },
      { onSuccess: (c) => void navigate(`/campaigns/${c.id}`) },
    );
  }

  return (
    <form className="wizard" onSubmit={submit}>
      <h1>Schedule a scan</h1>

      {create.error && <ErrorState error={create.error} action="create this campaign" />}

      <fieldset>
        <legend>Name</legend>
        <label htmlFor="campaign-name">What is this for?</label>
        <input
          id="campaign-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Nightly compliance scan"
          required
        />
      </fieldset>

      <fieldset>
        <legend>Projects</legend>
        <p className="field-hint">
          Each project gets its own scan. One project failing does not stop the others.
        </p>
        <CheckboxGroup
          name="projects"
          options={projects.map((p) => ({ value: p.id, label: p.name }))}
          selected={projectIds}
          onChange={setProjectIds}
        />
      </fieldset>

      <fieldset>
        <legend>Schedule</legend>

        <div className="preset-row" role="group" aria-label="Schedule presets">
          {SCHEDULE_PRESETS.map((p) => (
            <button
              key={p.id}
              type="button"
              className={`btn btn-sm${activePreset?.id === p.id ? ' btn-active' : ''}`}
              aria-pressed={activePreset?.id === p.id}
              onClick={() => setCron(p.cron)}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/*
          ⚠ THE EXPRESSION IS AN INPUT, NOT A READOUT. See the file comment: a
          preset-only UI cannot express "weekdays at 6am", and a schedule the
          customer cannot read is one they cannot audit.
        */}
        <label htmlFor="campaign-cron">Cron expression</label>
        <input
          id="campaign-cron"
          value={cron}
          onChange={(e) => setCron(e.target.value)}
          aria-describedby="cron-help"
          aria-invalid={cronError !== null}
          spellCheck={false}
        />
        <p id="cron-help" className="field-hint">
          minute hour day-of-month month day-of-week. Runs {describeCron(cron)}.
        </p>
        {cronError && (
          <p className="field-error" role="alert">
            {cronError}
          </p>
        )}

        {/*
          ⚠ AN IANA ZONE NAME, NEVER AN OFFSET. An offset is correct for half the
          year, and which half depends on the zone. The scheduler handles the
          transitions; storing "+05:30" would make that impossible.
        */}
        <label htmlFor="campaign-tz">Timezone</label>
        <input
          id="campaign-tz"
          value={timezone}
          onChange={(e) => setTimezone(e.target.value)}
          aria-describedby="tz-help"
          spellCheck={false}
        />
        <p id="tz-help" className="field-hint">
          An IANA name such as <code>Asia/Kolkata</code>. Daylight-saving transitions are handled
          for you: a run does not vanish in spring or happen twice in autumn.
        </p>
      </fieldset>

      <fieldset>
        <legend>What to produce</legend>

        <CheckboxGroup
          name="bom-types"
          label="BOM types"
          options={BOM_TYPES.map((t) => ({ value: t.token, label: t.label }))}
          selected={bomTypes}
          onChange={setBomTypes}
        />
        <CheckboxGroup
          name="levels"
          label="Levels"
          options={REPORT_LEVELS.map((l) => ({ value: l, label: l.replace(/_/g, ' ') }))}
          selected={levels}
          onChange={setLevels}
        />
        <CheckboxGroup
          name="standards"
          label="Standards"
          options={STANDARDS.map((s) => ({ value: s, label: s.toUpperCase() }))}
          selected={standards}
          onChange={setStandards}
        />
        <CheckboxGroup
          name="formats"
          label="Formats"
          options={FORMATS.map((f) => ({ value: f, label: f.toUpperCase() }))}
          selected={formats}
          onChange={setFormats}
        />
      </fieldset>

      {/*
        ⚠ PROBLEMS ARE LISTED, NOT HIDDEN BEHIND A DISABLED BUTTON. A greyed-out
        submit with no explanation is the most common accessibility failure in a
        form like this: a screen-reader user reaches an unreachable control and
        has nothing telling them why.
      */}
      {problems.length > 0 && (
        <div className="field-error" role="status">
          <p>Before this can be scheduled:</p>
          <ul>
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="wizard-actions">
        <button
          type="submit"
          className="btn btn-primary"
          disabled={problems.length > 0 || create.isPending}
        >
          {create.isPending ? 'Scheduling…' : 'Schedule it'}
        </button>
      </div>
    </form>
  );
}

interface CheckboxGroupProps {
  name: string;
  label?: string;
  options: Array<{ value: string; label: string }>;
  selected: string[];
  onChange: (next: string[]) => void;
}

function CheckboxGroup({ name, label, options, selected, onChange }: CheckboxGroupProps) {
  function toggle(value: string) {
    onChange(
      selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value],
    );
  }

  return (
    <div className="checkbox-group" role="group" aria-label={label ?? name}>
      {label && <span className="group-label">{label}</span>}
      {options.length === 0 && <p className="muted">Nothing to choose from yet.</p>}
      {options.map((o) => (
        <label key={o.value} className="checkbox">
          <input
            type="checkbox"
            name={name}
            value={o.value}
            checked={selected.includes(o.value)}
            onChange={() => toggle(o.value)}
          />
          {o.label}
        </label>
      ))}
    </div>
  );
}
