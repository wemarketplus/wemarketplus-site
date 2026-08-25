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
/**
 * The wire values, NAMED.
 *
 * Exists because the calendar had to write two of these from another module and
 * did it by typing the strings out, which is how it came to store
 * `'lunch_and_learn'` — a value with no member here, so `visitTypeLabel` printed
 * the raw slug and the log's exact-match Type filter could never select the row.
 * A varchar column will not catch that mistake; a named constant will.
 *
 * `FacilityVisit` is the newest member. The calendar has offered "Facility
 * visit" as one of its three choices since it was built, and this list had no
 * way to say it — so those rows were stored as the generic `InPerson` and the
 * Outreach Log reported a type the user never picked.
 */
export const VISIT_TYPE = {
  FacilityVisit: 'facility_visit',
  InPerson: 'in_person',
  Phone: 'phone',
  Email: 'email',
  Event: 'event',
  DropIn: 'drop_in',
  DropOff: 'drop_off',
  LunchLearn: 'lunch_learn',
} as const;
export type VisitType = (typeof VISIT_TYPE)[keyof typeof VISIT_TYPE];

export const VISIT_TYPE_OPTIONS: readonly EntitySelectOption[] = [
  { value: VISIT_TYPE.FacilityVisit, label: 'Facility visit' },
  { value: VISIT_TYPE.InPerson, label: 'In person' },
  { value: VISIT_TYPE.Phone, label: 'Phone' },
  { value: VISIT_TYPE.Email, label: 'Email' },
  { value: VISIT_TYPE.Event, label: 'Event' },
  { value: VISIT_TYPE.DropIn, label: 'Drop-in' },
  { value: VISIT_TYPE.DropOff, label: 'Drop-off / materials' },
  { value: VISIT_TYPE.LunchLearn, label: 'Lunch & learn' },
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
