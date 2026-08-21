import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { VisitFormValues } from '../schema/clOutreachSchema';
import type { ClOutreachUiState } from '../types/clOutreachTypes';

export const CL_OUTREACH_PAGE_SIZE = 20;

export const OUTREACH_VIEWS: ReadonlyArray<{
  value: ClOutreachUiState['view'];
  label: string;
}> = [
  { value: 'checkin', label: 'GPS check-in' },
  { value: 'log', label: 'Outreach log' },
];

/**
 * Visit type is a free-form varchar; the UI offers a stable set of buckets.
 *
 * `drop_off` and `lunch_learn` are the two the end-user guide calls out by name
 * ("including newer options like Drop-Off/Materials or Lunch & Learn, not just
 * 'visit'"). They are the two touchpoints a senior-living marketer reports on
 * separately — dropping brochures at a discharge desk is not the same call as
 * hosting a catered in-service — and folding both into "Drop-in"/"Event" is what
 * made the outreach log unable to answer what the team actually did last month.
 *
 * Adding values is safe in both directions: the column is a varchar with no enum
 * behind it, and `visitTypeLabel` falls back to the raw string, so rows already
 * carrying an older value keep rendering.
 */
export const VISIT_TYPE_OPTIONS: readonly EntitySelectOption[] = [
  { value: 'in_person', label: 'In person' },
  { value: 'phone', label: 'Phone' },
  { value: 'email', label: 'Email' },
  { value: 'event', label: 'Event' },
  { value: 'drop_in', label: 'Drop-in' },
  { value: 'drop_off', label: 'Drop-off / materials' },
  { value: 'lunch_learn', label: 'Lunch & learn' },
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
  // A PLACE, not a name: the picker writes the organisation's label AND the
  // gpsLat/gpsLng the table has carried (unwritten) since it was created.
  {
    name: 'locationName',
    label: 'Location / organization',
    type: 'location',
    latField: 'gpsLat',
    lngField: 'gpsLng',
    placeholder: 'Dallas Medical Group',
  },
  { name: 'miles', label: 'Miles', type: 'text', placeholder: '12.5' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'What was discussed…' },
];
