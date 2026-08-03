import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { TerritoryFormValues } from '../schema/territorySchema';

// Territory priority — mirrors backend TerritoryPriority enum.
export const TERRITORY_PRIORITY = {
  High: 'high',
  Medium: 'medium',
  Low: 'low',
} as const;

export type TerritoryPriority = (typeof TERRITORY_PRIORITY)[keyof typeof TERRITORY_PRIORITY];

export const TERRITORIES_PAGE_SIZE = 20;

// Human labels for the priority enum (Title Case from the lower values).
export const TERRITORY_PRIORITY_LABELS: Record<TerritoryPriority, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

// Options for the priority <select> in the form (leading blank = "unset").
export const TERRITORY_PRIORITY_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Select priority…' },
  ...Object.values(TERRITORY_PRIORITY).map((v) => ({
    value: v,
    label: TERRITORY_PRIORITY_LABELS[v],
  })),
];

// Field descriptors driving the create/edit modal (EntityFormModal).
export const TERRITORY_FIELDS: ReadonlyArray<EntityField<TerritoryFormValues>> = [
  { name: 'name', label: 'Territory name', full: true, placeholder: 'North Region' },
  { name: 'priority', label: 'Priority', type: 'select', options: TERRITORY_PRIORITY_OPTIONS },
  { name: 'assignedTo', label: 'Assigned to', type: 'lookup', placeholder: 'Unassigned' },
  { name: 'city', label: 'City', placeholder: 'Austin' },
  { name: 'state', label: 'State', placeholder: 'TX' },
  {
    name: 'zipCodes',
    label: 'Zip codes (comma separated)',
    full: true,
    placeholder: '78701, 78702, 78703',
  },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
