/**
 * Registered hardware devices.
 *
 * ⚠ A DEVICE USED TO BE A CONVENTION, NOT A THING. The level-0 row of a
 * versioned parts list carried a model, a serial and a manufacturer — but a new
 * import replaced the whole document, so nothing about "this device" survived
 * one, nothing was unique on serial, and a project could hold exactly one
 * hardware tree. A product line with three boards had nowhere to put two of
 * them.
 *
 * ⚠ REGISTRATION IS NOT DISCOVERY. Every field here is one a person typed.
 * Nothing in this module, or behind it, reaches a device.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { request } from './api';

export interface HardwareDevice {
  id: string;
  project_id: string;
  name: string;
  manufacturer: string;
  model_number: string;
  serial_number: string;
  lot_number: string;
  asset_tag: string;
  firmware_version: string;
  location: string;
  criticality: string;
  notes: string;
  created_at: string;
  updated_at: string;
  /** How many parts the device's current BOM document holds. */
  component_count: number;
  bom_document_id?: string;
  /**
   * When that document was generated.
   *
   * ⚠ EMPTY MEANS "no parts list yet", WHICH IS NOT THE SAME AS ZERO PARTS.
   * A device registered last month whose parts nobody has imported is a real
   * and important state; rendering it as "0 components" would read as a parts
   * list that was checked and found empty.
   */
  parts_updated_at?: string;
}

/**
 * DeviceFormField is one input, described by the server.
 *
 * ⚠ THE FORM IS DATA, NOT MARKUP. The field names and their CERT-In element
 * ids come from `docs/reference/certin-v2.0.yaml` via the profile, so a
 * guideline revision renames an input without a frontend release — the same
 * rule that forbids writing a field COUNT anywhere (CLAUDE.md invariant 2).
 */
export interface DeviceFormField {
  attr: string;
  name: string;
  field_id?: string;
  source_page?: number;
  /**
   * False for the four asset-management attributes AxeBOM adds. The form groups
   * on this so an asset tag never sits unlabelled beside a compliance element,
   * which would imply filling it in moves a coverage number. It does not.
   */
  certin: boolean;
  required: boolean;
  values?: string[];
  /** Render a textarea. Decided by the server, beside the field it describes. */
  multiline?: boolean;
}

/** The editable half — everything the server does not own. */
export type DeviceInput = Pick<
  HardwareDevice,
  | 'name'
  | 'manufacturer'
  | 'model_number'
  | 'serial_number'
  | 'lot_number'
  | 'asset_tag'
  | 'firmware_version'
  | 'location'
  | 'criticality'
  | 'notes'
>;

export const EMPTY_DEVICE: DeviceInput = {
  name: '',
  manufacturer: '',
  model_number: '',
  serial_number: '',
  lot_number: '',
  asset_tag: '',
  firmware_version: '',
  location: '',
  criticality: '',
  notes: '',
};

export function useDevices(projectId: string) {
  return useQuery({
    queryKey: ['hbom', projectId, 'devices'],
    queryFn: ({ signal }) =>
      request<{ devices: HardwareDevice[]; form: DeviceFormField[] }>(
        `/v1/hbom/${projectId}/devices`,
        { signal },
      ),
    enabled: projectId !== '',
  });
}

export function useCreateDevice(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: DeviceInput) =>
      request<HardwareDevice>(`/v1/hbom/${projectId}/devices`, { method: 'POST', body: input }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['hbom', projectId, 'devices'] }),
  });
}

export function useUpdateDevice(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: DeviceInput }) =>
      request<HardwareDevice>(`/v1/hbom/${projectId}/devices/${id}`, {
        method: 'PUT',
        body: input,
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['hbom', projectId, 'devices'] }),
  });
}

export function useDeleteDevice(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<void>(`/v1/hbom/${projectId}/devices/${id}`, { method: 'DELETE' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['hbom', projectId, 'devices'] }),
  });
}

/**
 * describeParts is what a device row says about its parts list.
 *
 * ⚠ THREE STATES, NOT TWO. "never imported", "imported and empty" and
 * "imported with N parts" are different facts, and collapsing the first two
 * into "0 components" tells a customer their board has no parts when nobody
 * has told the product about them yet.
 */
export function describeParts(d: HardwareDevice): string {
  if (!d.parts_updated_at) return 'No parts list imported yet';
  if (d.component_count === 0) return 'A parts list was imported and contained nothing';
  return `${d.component_count} part${d.component_count === 1 ? '' : 's'}`;
}
