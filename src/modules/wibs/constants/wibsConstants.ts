import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { WibFormValues } from '../schema/wibSchema';

// Workforce Investment Board status — mirrors backend WibStatus enum.
export const WIB_STATUS = {
  New: 'new',
  Researching: 'researching',
  Contacted: 'contacted',
  InDiscussion: 'in_discussion',
  Active: 'active',
  Inactive: 'inactive',
  Declined: 'declined',
} as const;

export type WibStatus = (typeof WIB_STATUS)[keyof typeof WIB_STATUS];

export const WIBS_PAGE_SIZE = 20;

// Title Case labels for the status enum values.
export const WIB_STATUS_LABELS: Record<WibStatus, string> = {
  new: 'New',
  researching: 'Researching',
  contacted: 'Contacted',
  in_discussion: 'In discussion',
  active: 'Active',
  inactive: 'Inactive',
  declined: 'Declined',
};

const STATUS_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Select status…' },
  ...Object.values(WIB_STATUS).map((v) => ({ value: v, label: WIB_STATUS_LABELS[v] })),
];

// Field descriptors driving the create/edit modal (EntityFormModal). Territory
// is assigned via a separate admin endpoint and is not part of this form.
export const WIB_FIELDS: ReadonlyArray<EntityField<WibFormValues>> = [
  { name: 'wibName', label: 'WIB name', full: true, placeholder: 'Central Region Workforce Board' },
  { name: 'sourceUrl', label: 'Source URL', full: true, placeholder: 'https://…' },
  { name: 'shortName', label: 'Short name', placeholder: 'CRWB' },
  { name: 'state', label: 'State', placeholder: 'TX' },
  { name: 'status', label: 'Status', type: 'select', options: STATUS_OPTIONS },
  { name: 'wibType', label: 'Type', placeholder: 'Local, regional…' },
  { name: 'wibPhone', label: 'Phone', type: 'tel', placeholder: '(555) 123-4567' },
  { name: 'wibEmail', label: 'Email', type: 'email', placeholder: 'contact@wib.org' },
  { name: 'website', label: 'Website', full: true, placeholder: 'https://…' },
  { name: 'maxAwardPerEin', label: 'Max award per EIN', type: 'number', placeholder: '0' },
  { name: 'matchRequirementPct', label: 'Match requirement (%)', type: 'number', placeholder: '0' },
  { name: 'nextSteps', label: 'Next steps', type: 'textarea', full: true },
  { name: 'blockers', label: 'Blockers', type: 'textarea', full: true },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
