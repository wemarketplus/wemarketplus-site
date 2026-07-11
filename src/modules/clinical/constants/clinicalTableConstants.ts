import type { PillProps } from '@/shared/ui/data-display';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import {
  BED_UNIT_STATUS,
  TELEHEALTH_STATUS,
  type BedUnitStatus,
  type TelehealthStatus,
} from './clinicalStatus';
import type { BedUnitFormValues } from '../schema/bedUnitSchema';
import type { TelehealthFormValues } from '../schema/telehealthSchema';

export const CLINICAL_PAGE_SIZE = 20;

// --- Bed units -------------------------------------------------------------

export const BED_UNIT_STATUS_LABELS: Record<BedUnitStatus, string> = {
  [BED_UNIT_STATUS.Available]: 'Available',
  [BED_UNIT_STATUS.Occupied]: 'Occupied',
  [BED_UNIT_STATUS.Reserved]: 'Reserved',
  [BED_UNIT_STATUS.Maintenance]: 'Maintenance',
  [BED_UNIT_STATUS.Discharged]: 'Discharged',
};

export const BED_UNIT_STATUS_PILL: Record<BedUnitStatus, PillProps['tone']> = {
  [BED_UNIT_STATUS.Available]: 'g',
  [BED_UNIT_STATUS.Occupied]: 'b',
  [BED_UNIT_STATUS.Reserved]: 'p',
  [BED_UNIT_STATUS.Maintenance]: 'y',
  [BED_UNIT_STATUS.Discharged]: 'r',
};

// --- Telehealth ------------------------------------------------------------

export const TELEHEALTH_STATUS_LABELS: Record<TelehealthStatus, string> = {
  [TELEHEALTH_STATUS.Scheduled]: 'Scheduled',
  [TELEHEALTH_STATUS.Completed]: 'Completed',
  [TELEHEALTH_STATUS.Cancelled]: 'Cancelled',
  [TELEHEALTH_STATUS.NoShow]: 'No show',
};

export const TELEHEALTH_STATUS_PILL: Record<TelehealthStatus, PillProps['tone']> = {
  [TELEHEALTH_STATUS.Scheduled]: 'b',
  [TELEHEALTH_STATUS.Completed]: 'g',
  [TELEHEALTH_STATUS.Cancelled]: 'r',
  [TELEHEALTH_STATUS.NoShow]: 'y',
};

// --- Select option lists (form + filters) ----------------------------------

const toOptions = (labels: Record<string, string>): readonly EntitySelectOption[] =>
  Object.entries(labels).map(([value, label]) => ({ value, label }));

export const BED_UNIT_STATUS_OPTIONS = toOptions(BED_UNIT_STATUS_LABELS);
export const TELEHEALTH_STATUS_OPTIONS = toOptions(TELEHEALTH_STATUS_LABELS);

// --- Create/edit form field descriptors ------------------------------------

export const BED_UNIT_FIELDS: ReadonlyArray<EntityField<BedUnitFormValues>> = [
  { name: 'facilityName', label: 'Facility', full: true, placeholder: 'Willow Creek Hospice' },
  { name: 'bedType', label: 'Bed type', placeholder: 'Private, Semi-private…' },
  { name: 'status', label: 'Status', type: 'select', options: BED_UNIT_STATUS_OPTIONS },
  { name: 'patientName', label: 'Patient', placeholder: 'Assigned patient (optional)' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'Unit notes…' },
];

export const TELEHEALTH_FIELDS: ReadonlyArray<EntityField<TelehealthFormValues>> = [
  { name: 'patientName', label: 'Patient', full: true, placeholder: 'Dorothy Harrison' },
  { name: 'providerName', label: 'Provider', placeholder: 'Dr. Alan Grant' },
  { name: 'sessionType', label: 'Session type', placeholder: 'Follow-up, Intake…' },
  { name: 'scheduledAt', label: 'Scheduled at', type: 'date' },
  { name: 'durationMin', label: 'Duration (min)', type: 'number', placeholder: '30' },
  { name: 'status', label: 'Status', type: 'select', options: TELEHEALTH_STATUS_OPTIONS },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'Visit notes…' },
];
