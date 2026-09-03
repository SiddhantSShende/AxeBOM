/**
 * HBOM types, queries, and the column-mapping vocabulary.
 *
 * ⚠ NOTHING HERE CLAIMS AxeBOM EXAMINED YOUR HARDWARE, AND THAT IS THE LINE.
 *
 * This module used to say every label must read "import" and none may read
 * "scan". That was right while a CSV and a form were the only ways a hardware
 * BOM could exist. `hbom-ecad` parses design files out of a repository or an
 * upload, which is a real scan of documents the customer wrote — the same act
 * as reading a committed lockfile — so "HBOM scan" is now accurate.
 *
 * What is still false, and what `hbom.test.ts` asserts against this file's own
 * exported strings, is any claim that AxeBOM inspected a physical device:
 * "scans your hardware", "inspects the device", "discovers hardware". No
 * open-source tool does that, and a customer who assumes otherwise finds out
 * while assembling audit evidence.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request, upload } from './api';

export interface HardwareComponent {
  id: string;
  parent_id: string | null;
  depth: number;
  quantity: number;

  product_name: string;
  product_version: string;
  model_number: string;
  serial_number: string;

  manufacturer_name: string;
  manufacturer_location: string;
  origin: string;

  /** Who sold the customer the PRODUCT. */
  supplier_info: string;
  supplier_location: string;
  /** Who supplied a COMPONENT to that product's manufacturer. Different. */
  component_supplier_info: string;
  component_supplier_location: string;

  firmware_version: string;
  criticality: '' | 'critical' | 'high' | 'medium' | 'low';
  technology_node: string;
  compliance: string[];
  power_supply: string;
  technical_specification: string;

  /** Judgements no parts list contains. The form is where these come from. */
  warranty_amc: string;
  license_info: string;
  test_result: string;

  findings: string[];
  /** attribute -> the provider that supplied it. */
  enriched_fields: Record<string, string>;

  /** Two CERT-In elements that could not round-trip through the API until now. */
  product_details: string;
  manufacturing_date: string;

  // --- manufacturing and procurement ---------------------------------------
  //
  // ⚠ NOT CERT-In ELEMENTS. They are scored against a separate profile and
  // must never move the compliance percentage. See
  // docs/reference/hbom-manufacturing-v1.yaml.

  /** Reference designators. A LIST: one line item covers many placements. */
  designators: string[];
  package_footprint: string;
  supplier_sku: string;
  preferred_supplier: string;
  /**
   * A STRING, not a number.
   *
   * ⚠ JSON NUMBERS ARE float64 AND 0.0018 DOES NOT SURVIVE THE ROUND TRIP
   * EXACTLY. The column is numeric(18,6); parsing to a JS number here and
   * sending it back would quietly change a price.
   */
  unit_price: string;
  currency: string;
  /** quantity x unit_price, computed by Postgres. Read-only. */
  extended_price?: string;
  do_not_populate: boolean;
  assembly_type: '' | 'smt' | 'tht' | 'mechanical';
  lifecycle_status: '' | 'active' | 'nrnd' | 'obsolete' | 'eol' | 'preview' | 'unknown';
  datasheet_url: string;

  alternates: HardwareAlternate[];

  children: HardwareComponent[];
}

/** An approved second source for a part. */
export interface HardwareAlternate {
  ordinal: number;
  manufacturer_name: string;
  model_number: string;
  supplier_info: string;
  supplier_sku: string;
  lifecycle_status: string;
  /**
   * ⚠ ALWAYS RENDERED BESIDE THE PART NUMBER, NEVER ALONE. An alternate's MPN
   * on its own reads as an approved substitution; "unverified" beside it is the
   * difference between a decision somebody made and one nobody has.
   */
  equivalence: 'drop-in' | 'functional' | 'unverified';
  approval_note: string;
}

export interface ImportPreview {
  /** What the tree will look like. Nothing is stored until confirmed. */
  roots: HardwareComponent[];
  component_count: number;
  max_depth: number;
  /** Headers no canonical column claimed. Shown, never swallowed. */
  unmapped_headers: string[];
  warnings: string[];
}

export interface ImportError {
  message: string;
  /** The row that broke, where the failure has one. */
  row?: number | undefined;
}

/**
 * The canonical columns an import understands.
 *
 * ⚠ `level` IS THE ONLY REQUIRED ONE, AND IT IS WHAT BUILDS THE TREE. Without
 * it every part becomes a sibling of the product rather than a part of it, and
 * the resulting BOM says something false about how the hardware is assembled.
 */
export const CANONICAL_COLUMNS = [
  {
    id: 'level',
    label: 'Level',
    required: true,
    hint: 'Builds the sub-component tree. 0 or 1 is the product; 1.2.1 outline form also works.',
  },
  { id: 'part_number', label: 'Part number', required: false, hint: '' },
  { id: 'description', label: 'Description', required: false, hint: '' },
  { id: 'quantity', label: 'Quantity', required: false, hint: '' },
  { id: 'manufacturer', label: 'Manufacturer', required: false, hint: '' },
  {
    id: 'manufacturer_location',
    label: 'Manufacturer location',
    required: false,
    hint: 'A supply-chain provenance signal (§10.2.1).',
  },
  { id: 'mpn', label: 'Manufacturer part number', required: false, hint: '' },
  {
    id: 'supplier',
    label: 'Component supplier',
    required: false,
    hint: 'Who supplied this part to the manufacturer of the larger product.',
  },
  { id: 'supplier_location', label: 'Component supplier location', required: false, hint: '' },
  {
    id: 'product_supplier',
    label: 'Product supplier',
    required: false,
    hint: 'Who sold YOU the product. A different relationship from the component supplier.',
  },
  {
    id: 'product_supplier_location',
    label: 'Product supplier location',
    required: false,
    hint: '',
  },
  { id: 'serial_number', label: 'Serial number', required: false, hint: '' },
  {
    id: 'firmware_version',
    label: 'Firmware version',
    required: false,
    hint: 'Required by §10.4.1.4.',
  },
  {
    id: 'origin',
    label: 'Origin',
    required: false,
    hint: 'Country or entity of origin. Required by §10.4.1.4.',
  },
  {
    id: 'criticality',
    label: 'Criticality',
    required: false,
    hint: 'critical, high, medium or low. Required by §10.4.1.4.',
  },
  { id: 'technology_node', label: 'Technology node', required: false, hint: 'For ICs: 7nm, 14nm…' },
  {
    id: 'compliance',
    label: 'Compliance',
    required: false,
    hint: 'RoHS, CE, REACH — comma separated.',
  },
  { id: 'power_supply', label: 'Power supply', required: false, hint: '' },
  { id: 'technical_specification', label: 'Technical specification', required: false, hint: '' },
  { id: 'manufacturing_date', label: 'Manufacturing date', required: false, hint: '' },
  {
    id: 'unit_cost',
    label: 'Unit price',
    required: false,
    // ⚠ THIS USED TO SAY "Accepted and ignored". It was true — there was no
    // column to store it in — and it is not any more.
    hint: 'Stored and reported. Not a CERT-In element, so it is scored separately.',
  },
  { id: 'currency', label: 'Currency', required: false, hint: 'ISO 4217, e.g. USD. Never guessed.' },
  {
    id: 'designator',
    label: 'Designators',
    required: false,
    hint: 'R1, C4, U2 — one line item can cover several placements.',
  },
  { id: 'footprint', label: 'Footprint / package', required: false, hint: '0402, QFN-48…' },
  { id: 'supplier_sku', label: 'Supplier SKU', required: false, hint: "The distributor's own order code." },
  { id: 'preferred_supplier', label: 'Preferred supplier', required: false, hint: '' },
  {
    id: 'dni',
    label: 'Do not populate',
    required: false,
    hint: 'DNP / DNI / NOFIT. The part is on the schematic and deliberately not fitted.',
  },
  { id: 'assembly_type', label: 'Assembly type', required: false, hint: 'SMT, THT or mechanical.' },
  {
    id: 'lifecycle',
    label: 'Lifecycle status',
    required: false,
    hint: 'Active, NRND, obsolete, EOL. NRND means buyable now and refused at the next respin.',
  },
  { id: 'datasheet', label: 'Datasheet URL', required: false, hint: '' },
] as const;

/** The closed sets, mirroring the database CHECK constraints. */
export const ASSEMBLY_TYPES = ['smt', 'tht', 'mechanical'] as const;
export const LIFECYCLE_VALUES = [
  'active',
  'nrnd',
  'obsolete',
  'eol',
  'preview',
  'unknown',
] as const;
export const EQUIVALENCE_VALUES = ['drop-in', 'functional', 'unverified'] as const;

/**
 * Elements no parts list contains.
 *
 * ⚠ THE UI SAYS SO EXPLICITLY, next to the coverage number. A customer looking
 * at 62% completeness deserves to know that four of the gaps are questions only
 * they can answer, not something the import failed to find.
 */
export const JUDGEMENT_FIELDS = [
  { id: 'warranty_amc', label: 'Warranty / AMC' },
  { id: 'license_info', label: 'Licence terms' },
  { id: 'test_result', label: 'Test result' },
  { id: 'criticality', label: 'Criticality rating' },
] as const;

export const CRITICALITY_VALUES = ['critical', 'high', 'medium', 'low'] as const;

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/** previewImport parses a file WITHOUT storing anything. */
export function usePreviewImport() {
  return useMutation({
    mutationFn: ({ file, mapping }: { file: File; mapping: Record<string, string> }) => {
      const form = new FormData();
      form.append('file', file);
      form.append('mapping', JSON.stringify(mapping));
      return upload<ImportPreview>('/v1/hbom/preview', form);
    },
  });
}

export function useConfirmImport(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ file, mapping }: { file: File; mapping: Record<string, string> }) => {
      const form = new FormData();
      form.append('file', file);
      form.append('mapping', JSON.stringify(mapping));
      form.append('project_id', projectId);
      return upload<{ bom_document_id: string }>('/v1/hbom/import', form);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['hbom', projectId] }),
  });
}

export function useHardwareTree(projectId: string) {
  return useQuery({
    queryKey: ['hbom', projectId],
    queryFn: ({ signal }) =>
      request<{ roots: HardwareComponent[] }>(`/v1/hbom/${projectId}`, { signal }),
    select: (d) => d.roots,
    enabled: projectId !== '',
  });
}

export function useSaveComponent(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (component: Partial<HardwareComponent>) =>
      request<HardwareComponent>(`/v1/hbom/${projectId}/components`, {
        method: 'POST',
        body: component,
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['hbom', projectId] }),
  });
}

/**
 * usePartLookup enriches by manufacturer part number.
 *
 * ⚠ IT IS ABSENT WHEN NO PROVIDER IS CONFIGURED, and the UI hides the control
 * rather than showing one that fails. A button that produces an error every
 * time teaches people to ignore errors.
 */
export function usePartLookup() {
  return useMutation({
    mutationFn: (mpns: string[]) =>
      request<{ provider: string; enrichments: Record<string, Partial<HardwareComponent>> }>(
        '/v1/hbom/lookup',
        { method: 'POST', body: { mpns } },
      ),
  });
}

export function usePartProvider() {
  return useQuery({
    queryKey: ['hbom', 'provider'],
    queryFn: ({ signal }) =>
      request<{ provider: string; configured: boolean }>('/v1/hbom/provider', { signal }),
    staleTime: 60 * 60 * 1000,
  });
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

/**
 * flatten walks a tree into rows for a table, preserving depth.
 *
 * ⚠ THE DEPTH IS A NUMBER ON THE ROW, NOT PADDING ON THE NAME. Indenting by
 * prepending spaces means the displayed value no longer equals the component's
 * name, so a search against it fails — and a leading space is exactly what a
 * spreadsheet export then has to escape.
 */
export function flatten(
  roots: HardwareComponent[],
): Array<{ component: HardwareComponent; depth: number }> {
  const out: Array<{ component: HardwareComponent; depth: number }> = [];

  function walk(node: HardwareComponent, depth: number) {
    out.push({ component: node, depth });
    for (const child of node.children ?? []) walk(child, depth + 1);
  }
  for (const root of roots) walk(root, 0);
  return out;
}

/** countComponents is the total across every tree. */
export function countComponents(roots: HardwareComponent[]): number {
  return flatten(roots).length;
}

/**
 * describeProvenance says where a component's values came from.
 *
 * A datasheet's claim about a manufacturer is a different kind of fact from a
 * serial number somebody read off the device, and presenting them identically
 * overstates one of them.
 */
export function describeProvenance(component: HardwareComponent): string {
  const sources = new Set(Object.values(component.enriched_fields ?? {}));
  if (sources.size === 0) return 'You supplied every value';
  return `Some values from ${[...sources].sort().join(', ')}`;
}


// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

/** One currency's total, and how much of the BOM it could not account for. */
export interface CostTotal {
  currency: string;
  /** A decimal STRING, never a JS number — see rollUp. */
  total: string;
  lines: number;
}

export interface CostRollUp {
  totals: CostTotal[];
  /** Lines with no usable price. A total that hides these is misleading. */
  unpriced: number;
}

/**
 * rollUp totals extended prices, per currency.
 *
 * ⚠ NEVER ACROSS CURRENCIES. 4.10 USD + 3.20 EUR is not a number. There is no
 * exchange rate in this data, and inventing one would put a fabricated figure
 * in front of somebody about to raise a purchase order.
 *
 * ⚠ AND THE UNPRICED COUNT IS PART OF THE RESULT, NOT AN AFTERTHOUGHT. A total
 * over a parts list where half the prices are missing is not the cost of the
 * product, and a reader who is not told will treat it as one. Returning it in
 * the same object makes it awkward to render the total without it.
 *
 * ⚠ INTEGER ARITHMETIC IN MICRO-UNITS, NOT FLOATING POINT. The prices arrive as
 * exact decimal strings from a numeric(18,6) column precisely so they never
 * pass through a float; 0.1 + 0.2 !== 0.3 in JavaScript, and the error
 * accumulates across every line of a 4000-part BOM.
 */
export function rollUp(components: HardwareComponent[]): CostRollUp {
  const micros = new Map<string, { total: bigint; lines: number }>();
  let unpriced = 0;

  for (const { component } of flatten(components)) {
    const amount = toMicros(component.extended_price ?? '');
    if (amount === null) {
      unpriced += 1;
      continue;
    }
    const currency = component.currency || 'unknown';
    const entry = micros.get(currency) ?? { total: 0n, lines: 0 };
    entry.total += amount;
    entry.lines += 1;
    micros.set(currency, entry);
  }

  const totals = [...micros.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([currency, { total, lines }]) => ({
      currency,
      total: fromMicros(total),
      lines,
    }));

  return { totals, unpriced };
}

/** Six decimal places, as an integer count of micro-units. */
function toMicros(value: string): bigint | null {
  const text = value.trim();
  if (!text || !/^\d+(\.\d+)?$/.test(text)) return null;
  const [whole = '0', fraction = ''] = text.split('.');
  return BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, '0').slice(0, 6));
}

function fromMicros(total: bigint): string {
  const whole = total / 1_000_000n;
  const fraction = (total % 1_000_000n).toString().padStart(6, '0');
  return `${whole}.${fraction}`;
}

/**
 * strandedParts are obsolete or end-of-life components with no approved
 * alternate.
 *
 * ⚠ THE MOST ACTIONABLE FACT IN A HARDWARE BOM, and one row among hundreds in
 * a table. Each of these stops a build when remaining stock runs out.
 */
export function strandedParts(components: HardwareComponent[]): HardwareComponent[] {
  return flatten(components)
    .map(({ component }) => component)
    .filter(
      (c) =>
        (c.lifecycle_status === 'obsolete' || c.lifecycle_status === 'eol') &&
        (c.alternates ?? []).length === 0,
    );
}

/**
 * describeAlternate renders a second source with its equivalence attached.
 *
 * ⚠ THE EQUIVALENCE NEVER TRAVELS SEPARATELY. A part number on its own reads as
 * an approved substitution. Defaulting an absent one to "unverified" rather
 * than to "drop-in" is the same rule the database CHECK enforces: asserting a
 * drop-in replacement is a decision about somebody's hardware, and defaulting
 * to the flattering value would make AxeBOM the author of a claim it never
 * checked.
 */
export function describeAlternate(alternate: HardwareAlternate): string {
  const id =
    alternate.model_number || alternate.supplier_sku || alternate.manufacturer_name || 'unnamed';
  return `${id} (${alternate.equivalence || 'unverified'})`;
}


// ---------------------------------------------------------------------------
// Per-supplier export
// ---------------------------------------------------------------------------
//
// ⚠ THE NATIVE REPLACEMENT FOR A GPL-3.0 DEPENDENCY WE DECLINED.
//
// `Kenneract/KiCAD-Multi-BOM-Plugin` does this and is GPL-3.0, which CLAUDE.md
// invariant 9 forbids importing; it has also been unmaintained since October
// 2024. The capability is grouping and formatting, so it is built here instead
// and the rejection is recorded in OSINT/tools.manifest.yaml with the reason.

/** A supplier's slice of the parts list, ready to hand to that supplier. */
export interface SupplierBOM {
  supplier: string;
  rows: string[][];
  header: string[];
}

/**
 * The column layouts suppliers actually accept.
 *
 * ⚠ NAMES AND ORDER ARE THE SUPPLIER'S, NOT OURS. A JLCPCB assembly upload is
 * rejected outright if the headers are not `Comment,Designator,Footprint,LCSC`;
 * "close enough" is a file somebody has to hand-edit at the point they are
 * trying to place an order.
 */
export type SupplierFormat = 'generic' | 'jlcpcb' | 'digikey';

export const SUPPLIER_FORMATS: { id: SupplierFormat; label: string; hint: string }[] = [
  { id: 'generic', label: 'Generic', hint: 'Every column, for a supplier with no fixed template.' },
  { id: 'jlcpcb', label: 'JLCPCB (PCBA)', hint: 'Comment, Designator, Footprint, LCSC.' },
  { id: 'digikey', label: 'Digi-Key', hint: 'Quantity and part number, as their upload expects.' },
];

/**
 * bySupplier splits a parts list into one BOM per preferred supplier.
 *
 * ⚠ DNP PARTS ARE EXCLUDED FROM EVERY SUPPLIER FILE. A do-not-populate line is
 * deliberately not fitted; ordering it wastes money, and having it on an
 * assembly file tells a factory to place a part the design says to leave off —
 * which is the expensive direction of that mistake.
 *
 * ⚠ PARTS WITH NO SUPPLIER ARE GROUPED UNDER AN EXPLICIT LABEL, NOT DROPPED. A
 * silently shorter file is one somebody orders from and then discovers is
 * missing parts.
 */
export function bySupplier(
  components: HardwareComponent[],
  format: SupplierFormat = 'generic',
): SupplierBOM[] {
  const groups = new Map<string, HardwareComponent[]>();

  for (const { component } of flatten(components)) {
    if (component.do_not_populate) continue;
    // A row with nothing to order by is not orderable from anyone.
    if (!component.model_number && !component.supplier_sku) continue;
    const supplier = component.preferred_supplier || 'No supplier recorded';
    groups.set(supplier, [...(groups.get(supplier) ?? []), component]);
  }

  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([supplier, parts]) => ({ supplier, ...formatFor(format, parts) }));
}

function formatFor(
  format: SupplierFormat,
  parts: HardwareComponent[],
): { header: string[]; rows: string[][] } {
  switch (format) {
    case 'jlcpcb':
      return {
        header: ['Comment', 'Designator', 'Footprint', 'LCSC'],
        rows: parts.map((c) => [
          c.product_details || c.product_name,
          c.designators.join(','),
          c.package_footprint,
          c.supplier_sku,
        ]),
      };
    case 'digikey':
      return {
        header: ['Quantity', 'Part Number', 'Customer Reference'],
        rows: parts.map((c) => [
          String(c.quantity),
          c.supplier_sku || c.model_number,
          c.designators.join(' '),
        ]),
      };
    default:
      return {
        header: [
          'Designators',
          'Quantity',
          'Part Number',
          'Manufacturer',
          'Supplier SKU',
          'Footprint',
          'Unit Price',
          'Currency',
          'Lifecycle',
        ],
        rows: parts.map((c) => [
          c.designators.join(', '),
          String(c.quantity),
          c.model_number,
          c.manufacturer_name,
          c.supplier_sku,
          c.package_footprint,
          c.unit_price,
          c.currency,
          c.lifecycle_status,
        ]),
      };
  }
}

/**
 * toCSV renders one supplier BOM.
 *
 * ⚠ FORMULA INJECTION IS ESCAPED HERE TOO, AND THIS FILE IS A SEPARATE OUTPUT
 * SURFACE FROM THE SERVER'S.
 *
 * `services/report/internal/render/safe` guards every server-rendered
 * spreadsheet (CLAUDE.md invariant 8). This CSV is built in the browser and
 * never passes through it — a component named `=cmd|'/c calc'!A1` would execute
 * when the supplier opens the file. The same rule, applied at the second place
 * a spreadsheet leaves this product.
 */
export function toCSV(bom: SupplierBOM): string {
  const lines = [bom.header, ...bom.rows].map((row) => row.map(csvCell).join(','));
  return lines.join('\r\n') + '\r\n';
}

const DANGEROUS_PREFIX = /^[=+\-@\t\r]/;

function csvCell(value: string): string {
  // A leading quote is the spreadsheet convention for "treat the rest as text",
  // and is not displayed when the file is opened.
  const guarded = DANGEROUS_PREFIX.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}
