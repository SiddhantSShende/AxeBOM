/**
 * What the CBOM screens may say the product found, and what they may not.
 *
 * ⚠ A CBOM IS WHAT THREE ENGINES COULD SEE, AND EACH SEES A SLICE. cbomkit-theia
 * reads key, certificate and crypto-config FILES and never code; cbomkit-action
 * reads Java and Python source without a build; cdxgen-cbom reads JS/TS call
 * sites. Go, C#, C/C++ and bytecode have no engine at all. A screen that says
 * "all cryptography" or "complete inventory" turns those gaps into a clean bill
 * the customer trusts — the failure CLAUDE.md invariant 12 exists to prevent.
 *
 * The browser-side twin of the HBOM and AIBOM guards, and it walks source files
 * for the same reason: a sentence rendered from a component is as much of a
 * claim as one exported from a module.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { deprecationLabel } from './crypto';

describe('the CBOM screens do not claim completeness', () => {
  const claims = [
    /\ball\s+(of\s+)?(the\s+|your\s+|its\s+)?cryptograph/i,
    /\bevery\s+(cryptographic\s+|crypto\s+)?(algorithm|key|asset|call)\s+(in|used|your)/i,
    /\bcomplete\s+(crypto(graphic)?\s+)?inventory\b/i,
    /\bfully\s+scanned\b/i,
    /\b(analy[sz]e[sd]?|analy[sz]ing|scan(s|ned|ning)?|read(s|ing)?|inspect(s|ed)?)\s+(your\s+|the\s+|its\s+)?(bytecode|jars?|wars?|compiled\s+(code|classes))\b/i,
  ];
  const negations = /\b(not|no|never|cannot|isn't|doesn't|rather than|instead of)\b/i;

  const flagged = (text: string) => claims.some((c) => c.test(text)) && !negations.test(text);

  it('would actually catch a claim', () => {
    // ⚠ THE FILE WALK BELOW PASSES TRIVIALLY IF THE NEGATION FILTER IS TOO
    // BROAD — a green test that proves nothing.
    expect(flagged('AxeBOM finds all cryptography in your repository')).toBe(true);
    expect(flagged('a complete inventory of your crypto')).toBe(true);
    expect(flagged('your code was fully scanned')).toBe(true);
    expect(flagged('we analyse your JARs for weak ciphers')).toBe(true);
    expect(flagged('every algorithm used in the project')).toBe(true);

    expect(flagged('JAR/WAR bytecode is not analysed')).toBe(false);
  });

  it('what is true is not flagged', () => {
    for (const text of [
      'Crypto assets appear here once the scan’s CBOM engines have run',
      'the scan’s Engine Coverage shows what each engine examined and what it could not see',
      'Derived from a cited reference table, not reported by an engine',
      'Java and Python were scanned from source without a build',
      'Private key found in source — rotate and remove',
    ]) {
      expect(flagged(text), `a true statement was flagged: ${text}`).toBe(false);
    }
  });

  it('never words unassessed as current', () => {
    expect(deprecationLabel('unassessed')).not.toMatch(/current|ok|safe/i);
  });

  it('no source file in the UI claims a complete crypto inventory', () => {
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
    expect(files.length).toBeGreaterThan(20);

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
      `these read as claims of a complete crypto inventory:\n${offenders.join('\n')}`,
    ).toHaveLength(0);
  });
});
