/**
 * The theme toggle.
 *
 * ⚠ THREE OPTIONS, NOT TWO. `System` is not the same as "whatever the OS said
 * when the page loaded": it means keep following, so a user whose OS switches
 * at dusk sees the app switch too. A two-state toggle silently opts everyone
 * out of that the first time they touch it.
 */

import { useTheme, type ThemeChoice } from '../design/theme';

const CHOICES: { value: ThemeChoice; label: string; glyph: string }[] = [
  { value: 'system', label: 'System', glyph: '◐' },
  { value: 'light', label: 'Light', glyph: '☀' },
  { value: 'dark', label: 'Dark', glyph: '☾' },
];

export function ThemeToggle() {
  const { choice, setChoice } = useTheme();

  return (
    <div className="theme-toggle" role="group" aria-label="Colour theme">
      {CHOICES.map((c) => (
        <button
          key={c.value}
          type="button"
          className="theme-option"
          aria-pressed={choice === c.value}
          onClick={() => setChoice(c.value)}
          // The glyph alone would be a colour-and-shape-only control; the label
          // is what a screen reader reads and what a tooltip shows.
          title={c.label}
        >
          <span aria-hidden="true">{c.glyph}</span>
          <span className="sr-only">{c.label}</span>
        </button>
      ))}
    </div>
  );
}
