import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { VisitFormValues } from '../schema/clOutreachSchema';
import type { ClOutreachUiState } from '../types/clOutreachTypes';

export const CL_OUTREACH_PAGE_SIZE = 20;

export const OUTREACH_VIEWS: ReadonlyArray<{
  value: ClOutreachUiState['view'];
  label: string;
}> = [
  { value: 'checkin', label: 'GPS check-in' },
  { value: 'mileage', label: 'Mileage' },
  { value: 'log', label: 'Outreach log' },
];

// Visit type is a free-form varchar; the UI offers a stable set of buckets.
export const VISIT_TYPE_OPTIONS: readonly EntitySelectOption[] = [
  { value: 'in_person', label: 'In person' },
  { value: 'phone', label: 'Phone' },
  { value: 'email', label: 'Email' },
  { value: 'event', label: 'Event' },
  { value: 'drop_in', label: 'Drop-in' },
];

export const VISIT_TYPE_LABELS: Record<string, string> = Object.fromEntries(
  VISIT_TYPE_OPTIONS.map((o) => [o.value, o.label]),
);

export function visitTypeLabel(type: string | null): string {
  if (!type) return '—';
  return VISIT_TYPE_LABELS[type] ?? type;
}

// Log-visit form field descriptors (drive EntityFormModal).
export const VISIT_FIELDS: ReadonlyArray<EntityField<VisitFormValues>> = [
  { name: 'visitDate', label: 'Visit date', type: 'date' },
  { name: 'visitType', label: 'Type', type: 'select', options: VISIT_TYPE_OPTIONS },
  { name: 'contactName', label: 'Contact', placeholder: 'Dr. Amanda Chen' },
  { name: 'locationName', label: 'Location / organization', placeholder: 'Dallas Medical Group' },
  { name: 'miles', label: 'Miles', type: 'text', placeholder: '12.5' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'What was discussed…' },
];
