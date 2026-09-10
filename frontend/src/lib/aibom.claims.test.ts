/**
 * What the AI screens may say the product did, and what they may not.
 *
 * ⚠ AN AIBOM IS DISCOVERY PLUS A PUBLIC LOOKUP, AND NEITHER IS AN EVALUATION.
 *
 * Three engines parse the customer's source for model references, prompts,
 * vector stores and inference calls; one asks a public API about a model
 * IDENTIFIER. AxeBOM does not run a model, measure it, test it for bias, audit
 * it, or confirm that a licence permits a customer's use.
 *
 * This is the browser-side twin of `workers/aibom/test_claims.py`, and it walks
 * source files for the same reason its HBOM predecessor does: a sentence
 * rendered from a component is as much of a claim as one exported from a module,
 * and the HBOM guard's own history is of prose going stale in exactly the file
 * nobody was watching.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('the AI screens do not claim to evaluate a model', () => {
  const claims = [
    /\b(evaluate|evaluates|evaluated|benchmark|benchmarks|benchmarked|test|tests|tested)\s+(your\s+|the\s+|their\s+|its\s+|each\s+)?model\b/i,
    /\bscans?\s+(your\s+|the\s+|their\s+)?model\b/i,
    /\baudit(s|ed)?\s+(your\s+|the\s+|their\s+|its\s+)?model\b/i,
    /\b(test|tests|tested|check|checks|checked)\s+for\s+bias\b/i,
    /\bbias\s+(test|testing|audit|evaluation)\b/i,
    /\bverif(y|ies|ied)\s+(your\s+|the\s+|its\s+)?licen[cs]e\b/i,
    /\bwatch(ing|es)?\s+(your\s+)?code\s+live\b/i,
    /\breal[- ]time\s+(code\s+)?monitoring\b/i,
    // ⚠ ADDED WITH THE GOVERNANCE SCREEN. A risk tier under Regulation (EU)
    // 2024/1689 depends on what a system is USED FOR, which is not in a
    // repository. AxeBOM records the operator's declaration and renders it back;
    // a screen that reads as if AxeBOM worked the tier out would turn a
    // customer's own assertion into our finding.
    /\b(axebom|we|it)\s+\w*\s?(classif|assess|determin|decid|infer)\w*\s+(the\s+|its\s+|your\s+)?(risk\s+)?(tier|level|category|classification)\b/i,
    // CLAUDE.md: AxeBOM reports violations against a configured policy and never
    // asserts compliance. The word is fine in "compliance profile" or
    // "compliance tag" — it is the PREDICATE that is forbidden.
    /\b(is|are|you'?re|fully|now)\s+compliant\b/i,
  ];
  const negations = /\b(not|no|never|cannot|is a lie|rather than|instead of)\b/i;

  const flagged = (text: string) => claims.some((c) => c.test(text)) && !negations.test(text);

  it('would actually catch a claim', () => {
    // ⚠ THE FILE WALK BELOW PASSES TRIVIALLY IF THE NEGATION FILTER IS TOO
    // BROAD, leaving a green test that proves nothing — a failure mode this
    // codebase has hit before.
    expect(flagged('AxeBOM evaluates the model against your policy')).toBe(true);
    expect(flagged('we tested the model for bias')).toBe(true);
    expect(flagged('this scans your model for weaknesses')).toBe(true);
    expect(flagged('AxeBOM verifies the licence permits your use')).toBe(true);
    expect(flagged('watch your code live as the scan runs')).toBe(true);
    expect(flagged('AxeBOM classifies the risk tier for you')).toBe(true);
    expect(flagged('your AI system is compliant with the EU AI Act')).toBe(true);

    expect(flagged('AxeBOM never evaluates the model')).toBe(false);
  });

  it('what is true is not flagged', () => {
    // A guard that only ever forbids is a guard nobody can work with: every
    // sentence here accurately describes what the product does, and flagging one
    // would push somebody to soften a true statement.
    for (const text of [
      'discovered in source at src/app.py:17',
      'the licence the model’s own card declares',
      'reported by the model’s own card',
      'three engines scan the repository for model references',
      'live discovery counts, updated as each engine reports',
      'Declared by you, not detected — AxeBOM has no way to know what a model is used for',
      'the compliance profile marks these elements user-supplied',
      'a compliance tag records the tier an operator declared',
      'reports violations against the policy you configured',
    ]) {
      expect(flagged(text), `a true statement was flagged: ${text}`).toBe(false);
    }
  });

  it('no source file in the UI claims to have evaluated a model', () => {
    const root = path.resolve(__dirname, '..');
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
          files.push(full);
        }
      }
    };
    walk(root);

    const offenders: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, index) => {
        const previous = index > 0 ? lines[index - 1] : '';
        if (claims.some((c) => c.test(line)) && !negations.test(previous + line)) {
          offenders.push(`${path.relative(root, file)}:${index + 1}: ${line.trim()}`);
        }
      });
    }

    expect(
      offenders,
      `these read as claims to have evaluated a model:\n${offenders.join('\n')}`,
    ).toHaveLength(0);
  });
});
