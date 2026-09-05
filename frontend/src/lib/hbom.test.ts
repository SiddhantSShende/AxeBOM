import fs from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { BOM_TYPES } from '../design/theme';
import {
  CANONICAL_COLUMNS,
  CRITICALITY_VALUES,
  JUDGEMENT_FIELDS,
  alternateWarning,
  blankAlternate,
  bySupplier,
  isAlternateIdentifiable,
  normalizeAlternates,
  countComponents,
  describeAlternate,
  describeProvenance,
  flatten,
  rollUp,
  strandedParts,
  toCSV,
  type HardwareComponent,
} from './hbom';

function component(overrides: Partial<HardwareComponent> = {}): HardwareComponent {
  return {
    id: 'c1',
    parent_id: null,
    depth: 0,
    quantity: 1,
    product_name: 'Gateway',
    product_version: '',
    model_number: 'ENC-GW-4400',
    serial_number: '',
    manufacturer_name: '',
    manufacturer_location: '',
    origin: '',
    supplier_info: '',
    supplier_location: '',
    component_supplier_info: '',
    component_supplier_location: '',
    firmware_version: '',
    criticality: '',
    technology_node: '',
    compliance: [],
    power_supply: '',
    technical_specification: '',
    warranty_amc: '',
    license_info: '',
    test_result: '',
    findings: [],
    enriched_fields: {},
    product_details: '',
    manufacturing_date: '',
    designators: [],
    package_footprint: '',
    supplier_sku: '',
    preferred_supplier: '',
    unit_price: '',
    currency: '',
    do_not_populate: false,
    assembly_type: '',
    lifecycle_status: '',
    datasheet_url: '',
    alternates: [],
    children: [],
    ...overrides,
  };
}

describe('the honest label', () => {
  // ⚠ "hbom scan" WAS ON THIS LIST AND IS NOT ANY MORE — the same narrowing
  // workers/hbom/test_hbom.py made, for the same reason.
  //
  // It belonged while a CSV and a form were the only ways in. `hbom-ecad`
  // parses the customer's own design files out of a repository or an upload,
  // which is a real scan of documents they wrote, so calling it one is accurate.
  //
  // ⚠ WHAT IS STILL FALSE, AND WHAT THIS GUARDS, IS THAT AxeBOM EXAMINED
  // PHYSICAL HARDWARE. Nothing inspects a device and enumerates its parts. So
  // the list got narrower on the phrase that became true and WIDER on the ones
  // that stayed false.
  //
  // This checks the strings this module EXPORTS — the ones that reach a user.
  //
  // ⚠ IT USED TO SAY A BUNDLER CANNOT READ FILES, SO ONLY EXPORTS COULD BE
  // GUARDED. That was wrong, and the cost of it was concrete: `ProjectWizard`
  // rendered "there is no HBOM scanner" to every user choosing a manual source,
  // for as long as hbom-ecad had existed, and nothing here was looking at that
  // file. Vitest runs under Node — `node:fs` works — so the source walk below
  // does exactly what workers/hbom/test_hbom.py does on the Python side.
  const claims = [
    /\b(hardware|device)\s+scan/i,
    /\bscans?\s+(your\s+|the\s+|their\s+)?(hardware|device)\b/i,
    /\b(discover|discovers|detect|detects|inspect|inspects|enumerate|enumerates)\s+(your\s+|the\s+|their\s+|its\s+)?(hardware|device|parts)\b/i,
  ];
  const negations = /\b(not|no|never|cannot|is a lie|rather than)\b/i;

  // Denials: claims that HBOM cannot be scanned, which hbom-ecad made false.
  const DENIALS = [
    /there is no HBOM scanner/i,
    /no scanner produces it/i,
    /HBOM is (imported|import), not scanned/i,
    /hardware is not scannable/i,
    /cannot (be )?scan(ned)? .{0,20}\bhardware\b/i,
  ];

  const flagged = (text: string) => claims.some((c) => c.test(text)) && !negations.test(text);

  it('no exported label or hint claims discovery', () => {
    const strings = [
      ...CANONICAL_COLUMNS.flatMap((c) => [c.label, c.hint]),
      ...JUDGEMENT_FIELDS.map((f) => f.label),
      describeProvenance(component()),
      describeProvenance(component({ enriched_fields: { origin: 'nexar' } })),
      // ⚠ THE BOM-TYPE SUMMARY WAS NOT GUARDED, AND THAT IS EXACTLY HOW IT
      // WENT STALE.
      //
      // It is the largest piece of prose about HBOM anywhere in the UI — the
      // subtitle of the /hbom page — and it still read "IMPORTED, not
      // discovered … no scanner produces it" long after hbom-ecad shipped,
      // while the engine table rendered directly beneath it listed that
      // engine. Every guard in this file watched a different string.
      ...BOM_TYPES.map((b) => b.summary),
    ];

    for (const text of strings) {
      expect(flagged(text), `reads as a discovery claim: ${text}`).toBe(false);
    }
  });

  it('the HBOM summary still denies examining hardware', () => {
    // ⚠ THE DISCOVERY GUARD ALONE WOULD PASS ON SILENCE. A summary that simply
    // stopped mentioning hardware provenance would clear every regex above
    // while dropping the one claim CLAUDE.md requires this product to keep
    // making — that it never looked at a device.
    const hbom = BOM_TYPES.find((b) => b.type === 'HBOM');
    expect(hbom).toBeDefined();
    expect(hbom!.summary).toMatch(/\bnothing here examined physical hardware\b/i);
  });

  it('would actually catch a claim', () => {
    // ⚠ THE CHECK ABOVE PASSES TRIVIALLY IF THE NEGATION FILTER IS TOO BROAD,
    // leaving a green test that proves nothing.
    //
    // The old example here was "Run an HBOM scan to find your parts", which
    // stopped being a lie when hbom-ecad shipped. These are the claims that are
    // still false.
    expect(flagged('AxeBOM scans your hardware for components')).toBe(true);
    expect(flagged('we inspect the device and enumerate its parts')).toBe(true);
    expect(flagged('this feature discovers hardware automatically')).toBe(true);
    expect(flagged('run an HBOM scan to discover your hardware')).toBe(true);

    expect(flagged('Hardware is not discoverable by any scan')).toBe(false);
  });

  it('no source file in the UI claims discovery, or denies the scan that exists', () => {
    // ⚠ THE TWIN OF workers/hbom/test_hbom.py's GUARD, AND IT WALKS FILES FOR
    // THE SAME REASON: the rule is about what we SAY, and a sentence rendered
    // from a component is as much of a claim as one exported from a module.
    //
    // Two directions, because the product got both wrong at different times:
    //   OVER-claiming — "scans your hardware" — was always guarded.
    //   UNDER-claiming — "there is no HBOM scanner" — was not, and shipped.
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
    const denials: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, i) => {
        // The preceding line joins the context so a negation written above the
        // claim still counts — the same two-line window the Python guard uses.
        const context = (i > 0 ? lines[i - 1] : '') + line;
        if (claims.some((c) => c.test(line)) && !negations.test(context)) {
          offenders.push(`${path.relative(root, file)}:${i + 1}: ${line.trim()}`);
        }
        // ⚠ THE UNDER-CLAIM. `hbom-ecad` exists; saying otherwise sends a user
        // away from a working path.
        //
        // Comments are exempt from THIS half only, and deliberately: the two
        // files that record what the wording used to be are doing the right
        // thing, and a guard that forbids naming the old mistake is a guard
        // that erases the reason the rule exists. The over-claim half above
        // still reads every line, comments included — a docstring asserting
        // that we scan hardware is as false as a rendered one.
        const isComment = /^\s*(\/\/|\/\*|\*|\{\/\*)/.test(line);
        // ⚠ A HAND-LISTED SET OF SENTENCES KEEPS MISSING THE NEXT ONE. The
        // first version of this caught the registration wizard's "there is no
        // HBOM scanner" and missed GenerateFlow's "HBOM is imported, not
        // scanned", which was thrown at users for just as long. So the pattern
        // is the SHAPE of the denial — HBOM plus a phrase asserting it is not
        // scannable — rather than two exact strings.
        if (!isComment && DENIALS.some((d) => d.test(line))) {
          denials.push(`${path.relative(root, file)}:${i + 1}: ${line.trim()}`);
        }
      });
    }

    expect(offenders, `discovery claims in UI source:\n${offenders.join('\n')}`).toEqual([]);
    expect(denials, `denies a scan that exists:\n${denials.join('\n')}`).toEqual([]);
  });

  it('does not flag a design-file scan, which is accurate', () => {
    // ⚠ THE OTHER HALF OF THE RULE. A guard that only ever forbids is one
    // nobody can work with, and the natural response to a narrower list is to
    // re-add "hbom scan" the next time somebody skims it — putting the honest
    // label back to forbidding a true sentence, which is how a rule ends up
    // ignored.
    expect(flagged('an HBOM scan parses the design files in your repository')).toBe(false);
    expect(flagged('run an HBOM scan to read your KiCad schematics')).toBe(false);
    expect(flagged('this HBOM scan found 42 line items in your parts list')).toBe(false);
  });
});

describe('canonical columns', () => {
  it('requires only the level column', () => {
    // ⚠ `level` BUILDS THE TREE. Without it every part becomes a sibling of the
    // product rather than a part of it, and the BOM says something false about
    // how the hardware is assembled.
    const required = CANONICAL_COLUMNS.filter((c) => c.required);
    expect(required.map((c) => c.id)).toEqual(['level']);
  });

  it('distinguishes the two supplier relationships by label', () => {
    // ⚠ "Supplier" ALONE IS THE FIELD SOMEBODY FILLS IN WITH WHICHEVER COMPANY
    // COMES TO MIND. Table 11 records two different relationships.
    const ids = CANONICAL_COLUMNS.map((c) => c.id);
    expect(ids).toContain('supplier');
    expect(ids).toContain('product_supplier');

    const componentSupplier = CANONICAL_COLUMNS.find((c) => c.id === 'supplier');
    const productSupplier = CANONICAL_COLUMNS.find((c) => c.id === 'product_supplier');
    expect(componentSupplier?.hint).toMatch(/manufacturer/i);
    expect(productSupplier?.hint).toMatch(/sold you/i);
    expect(componentSupplier?.label).not.toBe(productSupplier?.label);
  });

  it('cites the section for every §10.4.1.4 element', () => {
    // These four are absent from Table 11 and easy to dismiss as optional.
    for (const id of ['firmware_version', 'origin', 'criticality']) {
      const column = CANONICAL_COLUMNS.find((c) => c.id === id);
      expect(column?.hint, `${id} does not say why it matters`).toMatch(/10\.4\.1\.4/);
    }
  });

  // ⚠ THIS TEST USED TO REQUIRE THE WORD "ignored", AND THE PRODUCT CHANGED
  // UNDER IT. `unit_cost` was accepted and thrown away because there was no
  // column to store it in; migration 0011 added one. A hint still promising to
  // ignore a price the report now totals would be worse than no hint.
  it('says a stored non-CERT-In column is stored, and scored separately', () => {
    const cost = CANONICAL_COLUMNS.find((c) => c.id === 'unit_cost');
    expect(cost?.hint).toMatch(/stored/i);
    expect(cost?.hint, 'a reader must not think this moves the compliance number').toMatch(
      /separately/i,
    );
    expect(cost?.hint).not.toMatch(/ignored/i);
  });

  // Every manufacturing column the importer understands must be offered in the
  // mapping UI, or a customer's file carries data the product silently drops —
  // which is the exact failure the Go/Python drift caused on the server side.
  it('offers every manufacturing column', () => {
    const ids = CANONICAL_COLUMNS.map((c) => c.id);
    for (const id of [
      'designator',
      'footprint',
      'supplier_sku',
      'preferred_supplier',
      'dni',
      'assembly_type',
      'lifecycle',
      'currency',
    ]) {
      expect(ids, `${id} is not offered in the mapping UI`).toContain(id);
    }
  });
});

describe('judgement fields', () => {
  it('names the four no parts list contains', () => {
    expect(JUDGEMENT_FIELDS.map((f) => f.id).sort()).toEqual([
      'criticality',
      'license_info',
      'test_result',
      'warranty_amc',
    ]);
  });

  it('offers exactly the criticality values the database accepts', () => {
    // A fifth value in the UI is a 500 from a CHECK constraint, discovered by
    // the customer rather than by us.
    expect([...CRITICALITY_VALUES]).toEqual(['critical', 'high', 'medium', 'low']);
  });
});

describe('flatten', () => {
  it('preserves depth without touching the name', () => {
    // ⚠ INDENTING BY PADDING THE NAME breaks search against it, and a leading
    // space is exactly what a spreadsheet export then has to escape.
    const tree = [
      component({
        id: 'root',
        product_name: 'Gateway',
        children: [
          component({
            id: 'board',
            product_name: 'Mainboard',
            children: [component({ id: 'mcu', product_name: 'MCU' })],
          }),
        ],
      }),
    ];

    const rows = flatten(tree);
    expect(rows.map((r) => r.depth)).toEqual([0, 1, 2]);
    expect(rows.map((r) => r.component.product_name)).toEqual(['Gateway', 'Mainboard', 'MCU']);
    for (const row of rows) {
      expect(row.component.product_name).toBe(row.component.product_name.trim());
    }
  });

  it('counts every node, not just the roots', () => {
    const tree = [
      component({ id: 'a', children: [component({ id: 'b' }), component({ id: 'c' })] }),
      component({ id: 'd' }),
    ];
    expect(countComponents(tree)).toBe(4);
  });

  it('survives a node with no children array', () => {
    const partial = { ...component(), children: undefined } as unknown as HardwareComponent;
    expect(() => flatten([partial])).not.toThrow();
  });
});

describe('describeProvenance', () => {
  it('says the customer supplied everything when nothing was enriched', () => {
    expect(describeProvenance(component())).toBe('You supplied every value');
  });

  it('names the providers, sorted and deduped', () => {
    // ⚠ A DATASHEET'S CLAIM IS A DIFFERENT KIND OF FACT from a serial number
    // read off the device. Presenting them identically overstates one.
    const enriched = component({
      enriched_fields: {
        manufacturer_location: 'nexar',
        origin: 'mouser',
        technology_node: 'nexar',
      },
    });
    expect(describeProvenance(enriched)).toBe('Some values from mouser, nexar');
  });

  it('is stable across calls', () => {
    const enriched = component({
      enriched_fields: { a: 'nexar', b: 'mouser', c: 'nexar', d: 'mouser' },
    });
    const first = describeProvenance(enriched);
    for (let i = 0; i < 20; i += 1) {
      expect(describeProvenance(enriched)).toBe(first);
    }
  });
});

describe('cost roll-up', () => {
  const part = (over: Partial<HardwareComponent> = {}): HardwareComponent => ({
    ...component(),
    children: [],
    ...over,
  });

  it('never sums across currencies', () => {
    // ⚠ 4.10 USD + 3.20 EUR IS NOT A NUMBER. There is no exchange rate in this
    // data, and inventing one would put a fabricated figure in front of
    // somebody about to raise a purchase order.
    const { totals } = rollUp([
      part({ extended_price: '4.100000', currency: 'USD' }),
      part({ extended_price: '3.200000', currency: 'EUR' }),
    ]);

    expect(totals).toHaveLength(2);
    expect(totals.map((t) => t.currency)).toEqual(['EUR', 'USD']);
    expect(totals.every((t) => t.total !== '7.300000')).toBe(true);
  });

  it('adds in exact decimal, not floating point', () => {
    // ⚠ 0.1 + 0.2 !== 0.3 IN JAVASCRIPT. The prices are exact decimal strings
    // from a numeric(18,6) column precisely so they never touch a float, and
    // the error would accumulate across every line of a 4000-part BOM.
    const { totals } = rollUp([
      part({ extended_price: '0.100000', currency: 'USD' }),
      part({ extended_price: '0.200000', currency: 'USD' }),
    ]);

    expect(totals[0]!.total).toBe('0.300000');
  });

  it('counts the lines it could not price', () => {
    // A total over a parts list where half the prices are missing is not the
    // cost of the product, and a reader who is not told will treat it as one.
    const { totals, unpriced } = rollUp([
      part({ extended_price: '1.500000', currency: 'USD' }),
      part({ extended_price: '', currency: '' }),
      part({ extended_price: 'not a number', currency: 'USD' }),
    ]);

    expect(totals[0]!.total).toBe('1.500000');
    expect(totals[0]!.lines).toBe(1);
    expect(unpriced).toBe(2);
  });

  it('walks the whole tree, not just the roots', () => {
    const root = part({ extended_price: '', currency: '' });
    root.children = [part({ extended_price: '2.000000', currency: 'USD' })];

    expect(rollUp([root]).totals[0]!.total).toBe('2.000000');
  });
});

describe('stranded parts', () => {
  const part = (over: Partial<HardwareComponent> = {}): HardwareComponent => ({
    ...component(),
    children: [],
    alternates: [],
    ...over,
  });

  it('is an obsolete part with no approved alternate', () => {
    // ⚠ THE MOST ACTIONABLE FACT IN A HARDWARE BOM. Each of these stops a build
    // when remaining stock runs out; a part with an alternate does not.
    const stranded = strandedParts([
      part({ lifecycle_status: 'active' }),
      part({ lifecycle_status: 'obsolete', model_number: 'DEAD-1' }),
      part({
        lifecycle_status: 'eol',
        model_number: 'COVERED-1',
        alternates: [
          {
            ordinal: 0,
            manufacturer_name: '',
            model_number: 'ALT-1',
            supplier_info: '',
            supplier_sku: '',
            lifecycle_status: '',
            equivalence: 'drop-in',
            approval_note: '',
          },
        ],
      }),
    ]);

    expect(stranded.map((p) => p.model_number)).toEqual(['DEAD-1']);
  });
});

describe('describeAlternate', () => {
  it('always shows the equivalence beside the part number', () => {
    // ⚠ A PART NUMBER ON ITS OWN READS AS AN APPROVED SUBSTITUTION.
    const base = {
      ordinal: 0,
      manufacturer_name: '',
      supplier_info: '',
      supplier_sku: '',
      lifecycle_status: '',
      approval_note: '',
    };

    expect(describeAlternate({ ...base, model_number: 'ALT-1', equivalence: 'drop-in' })).toBe(
      'ALT-1 (drop-in)',
    );
    // An absent equivalence defaults to the CONSERVATIVE value, never the
    // flattering one — the same rule the database CHECK enforces.
    expect(
      describeAlternate({
        ...base,
        model_number: 'ALT-2',
        equivalence: '' as unknown as 'unverified',
      }),
    ).toBe('ALT-2 (unverified)');
  });
});

describe('per-supplier export', () => {
  const part = (over: Partial<HardwareComponent> = {}): HardwareComponent => ({
    ...component(),
    children: [],
    alternates: [],
    ...over,
  });

  const parts = [
    part({
      model_number: 'RC0402',
      supplier_sku: 'C25744',
      preferred_supplier: 'JLCPCB',
      designators: ['R1', 'R4'],
      package_footprint: '0402',
      product_details: '10k 1%',
      quantity: 2,
    }),
    part({
      model_number: 'STM32',
      supplier_sku: '497-1234-ND',
      preferred_supplier: 'Digi-Key',
      designators: ['U1'],
      quantity: 1,
    }),
    // ⚠ DELIBERATELY NOT FITTED. Ordering it wastes money, and having it on an
    // assembly file tells a factory to place a part the design says to omit.
    part({ model_number: 'TP-1', preferred_supplier: 'JLCPCB', do_not_populate: true }),
    // Orderable, but nobody is named — grouped explicitly rather than dropped.
    part({ model_number: 'MYSTERY-1', preferred_supplier: '' }),
  ];

  it('splits by supplier and excludes do-not-populate parts', () => {
    const boms = bySupplier(parts);
    expect(boms.map((b) => b.supplier)).toEqual(['Digi-Key', 'JLCPCB', 'No supplier recorded']);

    const jlc = boms.find((b) => b.supplier === 'JLCPCB')!;
    expect(jlc.rows).toHaveLength(1);
    expect(jlc.rows[0]!.join(' ')).not.toContain('TP-1');
  });

  it('never silently drops a part nobody supplies', () => {
    // A shorter file is one somebody orders from and then discovers is missing
    // parts.
    const unassigned = bySupplier(parts).find((b) => b.supplier === 'No supplier recorded');
    expect(unassigned?.rows[0]).toContain('MYSTERY-1');
  });

  it("uses each supplier's own column names and order", () => {
    // ⚠ A JLCPCB UPLOAD IS REJECTED OUTRIGHT IF THE HEADERS ARE WRONG. "Close
    // enough" is a file somebody hand-edits at the moment they are placing an
    // order.
    const jlc = bySupplier(parts, 'jlcpcb').find((b) => b.supplier === 'JLCPCB')!;
    expect(jlc.header).toEqual(['Comment', 'Designator', 'Footprint', 'LCSC']);
    expect(jlc.rows[0]).toEqual(['10k 1%', 'R1,R4', '0402', 'C25744']);

    const dk = bySupplier(parts, 'digikey').find((b) => b.supplier === 'Digi-Key')!;
    expect(dk.header).toEqual(['Quantity', 'Part Number', 'Customer Reference']);
    expect(dk.rows[0]).toEqual(['1', '497-1234-ND', 'U1']);
  });

  it('escapes formula injection in the browser-built CSV', () => {
    // ⚠ THIS FILE NEVER PASSES THROUGH THE SERVER'S render/safe GUARD. A part
    // named `=cmd|'/c calc'!A1` executes when the supplier opens it — the same
    // vulnerability class, at the second place a spreadsheet leaves the
    // product.
    const hostile = bySupplier([part({ model_number: "=cmd|'/c calc'!A1", supplier_sku: '+1+1' })]);
    const csv = toCSV(hostile[0]!);

    for (const cell of csv.split(/[\r\n,]/)) {
      const value = cell.replace(/^"|"$/g, '');
      expect(/^[=+\-@]/.test(value), `unescaped: ${value}`).toBe(false);
    }
    expect(csv).toContain("'=cmd");
  });
});

// ---------------------------------------------------------------------------
// Editing alternates
// ---------------------------------------------------------------------------

describe('alternate editing', () => {
  it('starts a new alternate at unverified, never at an approved value', () => {
    // ⚠ THE DEFAULT STATE OF AN UNFINISHED EDIT MUST NOT BE AN APPROVED
    // SUBSTITUTION. If the editor opened on "drop-in", a row somebody added and
    // walked away from would read as a decision nobody made — which is the exact
    // thing the equivalence field exists to prevent.
    expect(blankAlternate(0).equivalence).toBe('unverified');
    expect(blankAlternate(3).ordinal).toBe(3);
  });

  it('treats a row that names nothing as not identifiable', () => {
    // Mirrors the hardware_alternate_identifiable CHECK.
    expect(isAlternateIdentifiable(blankAlternate(0))).toBe(false);
    expect(isAlternateIdentifiable({ ...blankAlternate(0), manufacturer_name: 'Panasonic' })).toBe(
      true,
    );
    expect(isAlternateIdentifiable({ ...blankAlternate(0), supplier_sku: 'P10-ND' })).toBe(true);
    // Whitespace is not an identifier.
    expect(isAlternateIdentifiable({ ...blankAlternate(0), model_number: '   ' })).toBe(false);
  });

  it('drops blank rows and renumbers the survivors', () => {
    const normalized = normalizeAlternates([
      { ...blankAlternate(0), model_number: 'A' },
      blankAlternate(1),
      { ...blankAlternate(2), model_number: 'C' },
    ]);
    expect(normalized.map((a) => a.model_number)).toEqual(['A', 'C']);
    // ⚠ RENUMBERED, so ordinal stays the position a reader sees rather than a
    // gap left by a deleted row.
    expect(normalized.map((a) => a.ordinal)).toEqual([0, 1]);
  });

  it('warns that an obsolete alternate is not a second source', () => {
    // ⚠ THE MOST MISLEADING ROW IN A HARDWARE BOM: a populated Alternates
    // column against a part whose alternate is itself unbuyable. A reader skims
    // past it precisely because the column is not empty.
    for (const status of ['obsolete', 'eol']) {
      const warning = alternateWarning({ ...blankAlternate(0), lifecycle_status: status });
      expect(warning).toContain('itself obsolete');
    }
  });

  it('warns that an unverified alternate is a candidate, not an approval', () => {
    const warning = alternateWarning(blankAlternate(0));
    expect(warning).toContain('candidate');
    expect(warning).not.toBe('');
  });

  it('does not warn about a verified, active alternate', () => {
    expect(
      alternateWarning({
        ...blankAlternate(0),
        equivalence: 'drop-in',
        lifecycle_status: 'active',
      }),
    ).toBe('');
  });

  it('never lets a part number reach the UI without its equivalence', () => {
    // describeAlternate is what the read-only tree renders. The editor and the
    // table have to agree that the qualifier is inseparable from the identifier.
    const described = describeAlternate({ ...blankAlternate(0), model_number: 'ERJ-2RKF1002X' });
    expect(described).toContain('ERJ-2RKF1002X');
    expect(described).toContain('unverified');
  });
});
