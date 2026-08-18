import { describe, expect, it } from 'vitest';
import {
  CANONICAL_COLUMNS,
  CRITICALITY_VALUES,
  JUDGEMENT_FIELDS,
  countComponents,
  describeProvenance,
  flatten,
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
    children: [],
    ...overrides,
  };
}

describe('the honest label', () => {
  // ⚠ THERE IS NO OPEN-SOURCE HBOM SCANNER. An "HBOM scan" button that reads a
  // CSV is a lie the customer discovers while assembling audit evidence, having
  // assumed for months that something was watching their hardware.
  //
  // This checks the strings this module EXPORTS — the ones that reach a user.
  // The worker's own source is walked by `workers/hbom/test_hbom.py`, which can
  // read files; a bundler cannot, and a test that pretends to would be checking
  // nothing.
  const claims = [/hbom scan/i, /scan (your )?hardware/i, /hardware scan/i, /discovers? parts/i];
  const negations = /\b(not|no|never|cannot|is a lie|rather than)\b/i;

  const flagged = (text: string) => claims.some((c) => c.test(text)) && !negations.test(text);

  it('no exported label or hint claims discovery', () => {
    const strings = [
      ...CANONICAL_COLUMNS.flatMap((c) => [c.label, c.hint]),
      ...JUDGEMENT_FIELDS.map((f) => f.label),
      describeProvenance(component()),
      describeProvenance(component({ enriched_fields: { origin: 'nexar' } })),
    ];

    for (const text of strings) {
      expect(flagged(text), `reads as a discovery claim: ${text}`).toBe(false);
    }
  });

  it('would actually catch a claim', () => {
    // ⚠ THE CHECK ABOVE PASSES TRIVIALLY IF THE NEGATION FILTER IS TOO BROAD,
    // leaving a green test that proves nothing.
    expect(flagged('Run an HBOM scan to find your parts')).toBe(true);
    expect(flagged('Hardware is not discoverable by any scan')).toBe(false);
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

  it('says plainly which columns are accepted and ignored', () => {
    const cost = CANONICAL_COLUMNS.find((c) => c.id === 'unit_cost');
    expect(cost?.hint).toMatch(/ignored/i);
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
