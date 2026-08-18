/**
 * HBOM types, queries, and the column-mapping vocabulary.
 *
 * ⚠ EVERY LABEL IN THIS MODULE SAYS "IMPORT". NONE SAYS "SCAN".
 *
 * There is no open-source tool that inspects a physical device and enumerates
 * its parts, and this product does not pretend otherwise. An "HBOM scan" button
 * that reads a CSV is a lie the customer discovers while assembling evidence for
 * an audit, having assumed for months that something was watching their
 * hardware. `hbom.test.ts` asserts this file's own strings.
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

  children: HardwareComponent[];
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
    label: 'Unit cost',
    required: false,
    hint: 'Accepted and ignored — not a CERT-In element.',
  },
] as const;

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
    queryFn: () => request<{ roots: HardwareComponent[] }>(`/v1/hbom/${projectId}`),
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
    queryFn: () => request<{ provider: string; configured: boolean }>('/v1/hbom/provider'),
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
