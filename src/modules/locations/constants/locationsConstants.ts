import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { LocationFormValues } from '../schema/locationSchema';

// Employer location status — mirrors backend LocationStatus enum.
export const LOCATION_STATUS = {
  Active: 'active',
  Inactive: 'inactive',
  Prospect: 'prospect',
} as const;

export type LocationStatus = (typeof LOCATION_STATUS)[keyof typeof LOCATION_STATUS];

export const LOCATIONS_PAGE_SIZE = 20;

// Human labels for the status enum (Title Case from the lower values).
export const LOCATION_STATUS_LABELS: Record<LocationStatus, string> = {
  active: 'Active',
  inactive: 'Inactive',
  prospect: 'Prospect',
};

// Options for the status <select> in the form (leading blank = "unset").
export const LOCATION_STATUS_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Select status…' },
  ...Object.values(LOCATION_STATUS).map((v) => ({ value: v, label: LOCATION_STATUS_LABELS[v] })),
];

// Options for the status filter <select> (leading blank = "all").
export const LOCATION_STATUS_FILTER_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'All statuses' },
  ...Object.values(LOCATION_STATUS).map((v) => ({ value: v, label: LOCATION_STATUS_LABELS[v] })),
];

// Field descriptors driving the create/edit modal (EntityFormModal). companyId is
// create-only on the backend; we keep it in the form but the update mapper drops
// it (reparenting is not allowed via update).
export const LOCATION_FIELDS: ReadonlyArray<EntityField<LocationFormValues>> = [
  { name: 'locationName', label: 'Location name', full: true, placeholder: 'Downtown Warehouse' },
  { name: 'status', label: 'Status', type: 'select', options: LOCATION_STATUS_OPTIONS },
  { name: 'employeeCount', label: 'Employee count', type: 'number', placeholder: '0' },
  { name: 'city', label: 'City', placeholder: 'Austin' },
  { name: 'county', label: 'County', placeholder: 'Travis' },
  { name: 'state', label: 'State', placeholder: 'TX' },
  { name: 'address', label: 'Address', full: true, placeholder: '123 Main St' },
  { name: 'companyId', label: 'Company id (UUID)', placeholder: 'optional, set at creation only' },
  { name: 'wibId', label: 'WIB id (UUID)', placeholder: 'optional, set at creation only' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
