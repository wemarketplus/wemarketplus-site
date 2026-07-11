import type { PillProps } from '@/shared/ui/data-display';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import {
  APARTMENT_STATUS,
  HOUSEKEEPING_STATUS,
  MAINTENANCE_STATUS,
  MAKE_READY_CATEGORY,
  MAKE_READY_STATUS,
  TICKET_PRIORITY,
  type ApartmentStatus,
  type HousekeepingStatus,
  type MaintenanceStatus,
  type MakeReadyCategory,
  type MakeReadyStatus,
  type TicketPriority,
} from './clOperationsApiConstants';
import type { ClOperationsUiState } from '../types/clOperationsTypes';
import type {
  MaintenanceFormValues,
  HousekeepingFormValues,
  CommunityFormValues,
} from '../schema/clOperationsSchema';

export const CL_OPS_PAGE_SIZE = 20;

export const OPERATIONS_VIEWS: ReadonlyArray<{
  value: ClOperationsUiState['view'];
  label: string;
}> = [
  { value: 'communities', label: 'Communities' },
  { value: 'inventory', label: 'Apartments' },
  { value: 'make-ready', label: 'Make-ready' },
  { value: 'maintenance', label: 'Maintenance' },
  { value: 'housekeeping', label: 'Housekeeping' },
];

export const COMMUNITY_FIELDS: ReadonlyArray<EntityField<CommunityFormValues>> = [
  { name: 'name', label: 'Community name', full: true, placeholder: 'Sunrise Senior Living' },
  { name: 'city', label: 'City', placeholder: 'Dallas' },
  { name: 'state', label: 'State', placeholder: 'TX' },
  { name: 'phone', label: 'Phone', type: 'tel', placeholder: '(214) 555-0100' },
  { name: 'totalUnits', label: 'Total units', type: 'text', placeholder: '8' },
  { name: 'address', label: 'Address', full: true, placeholder: '123 Main St' },
];

// --- labels --------------------------------------------------------------

export const APARTMENT_STATUS_LABELS: Record<ApartmentStatus, string> = {
  [APARTMENT_STATUS.Available]: 'Available',
  [APARTMENT_STATUS.Occupied]: 'Occupied',
  [APARTMENT_STATUS.Reserved]: 'Reserved',
  [APARTMENT_STATUS.OnNotice]: 'On notice',
  [APARTMENT_STATUS.MakeReady]: 'Make-ready',
  [APARTMENT_STATUS.Maintenance]: 'Maintenance',
  [APARTMENT_STATUS.Offline]: 'Offline',
};

export const MAINTENANCE_STATUS_LABELS: Record<MaintenanceStatus, string> = {
  [MAINTENANCE_STATUS.Open]: 'Open',
  [MAINTENANCE_STATUS.InProgress]: 'In progress',
  [MAINTENANCE_STATUS.Scheduled]: 'Scheduled',
  [MAINTENANCE_STATUS.Completed]: 'Completed',
  [MAINTENANCE_STATUS.Cancelled]: 'Cancelled',
};

export const MAKE_READY_STATUS_LABELS: Record<MakeReadyStatus, string> = {
  [MAKE_READY_STATUS.Pending]: 'Pending',
  [MAKE_READY_STATUS.InProgress]: 'In progress',
  [MAKE_READY_STATUS.Completed]: 'Completed',
  [MAKE_READY_STATUS.Blocked]: 'Blocked',
};

export const MAKE_READY_CATEGORY_LABELS: Record<MakeReadyCategory, string> = {
  [MAKE_READY_CATEGORY.Maintenance]: 'Maintenance',
  [MAKE_READY_CATEGORY.Housekeeping]: 'Housekeeping',
  [MAKE_READY_CATEGORY.Inspection]: 'Inspection',
  [MAKE_READY_CATEGORY.General]: 'General',
};

export const HOUSEKEEPING_STATUS_LABELS: Record<HousekeepingStatus, string> = {
  [HOUSEKEEPING_STATUS.Pending]: 'Not started',
  [HOUSEKEEPING_STATUS.InProgress]: 'In progress',
  [HOUSEKEEPING_STATUS.Completed]: 'Completed',
  [HOUSEKEEPING_STATUS.Skipped]: 'Skipped',
};

export const TICKET_PRIORITY_LABELS: Record<TicketPriority, string> = {
  [TICKET_PRIORITY.Urgent]: 'Urgent',
  [TICKET_PRIORITY.High]: 'High',
  [TICKET_PRIORITY.Medium]: 'Med',
  [TICKET_PRIORITY.Low]: 'Low',
};

// --- pill tones ----------------------------------------------------------

export const APARTMENT_STATUS_PILL: Record<ApartmentStatus, PillProps['tone']> = {
  [APARTMENT_STATUS.Available]: 'g',
  [APARTMENT_STATUS.Occupied]: 'b',
  [APARTMENT_STATUS.Reserved]: 'p',
  [APARTMENT_STATUS.OnNotice]: 'y',
  [APARTMENT_STATUS.MakeReady]: 'y',
  [APARTMENT_STATUS.Maintenance]: 'r',
  [APARTMENT_STATUS.Offline]: 'b',
};

export const MAINTENANCE_STATUS_PILL: Record<MaintenanceStatus, PillProps['tone']> = {
  [MAINTENANCE_STATUS.Open]: 'r',
  [MAINTENANCE_STATUS.InProgress]: 'y',
  [MAINTENANCE_STATUS.Scheduled]: 'b',
  [MAINTENANCE_STATUS.Completed]: 'g',
  [MAINTENANCE_STATUS.Cancelled]: 'b',
};

export const MAKE_READY_STATUS_PILL: Record<MakeReadyStatus, PillProps['tone']> = {
  [MAKE_READY_STATUS.Pending]: 'y',
  [MAKE_READY_STATUS.InProgress]: 'b',
  [MAKE_READY_STATUS.Completed]: 'g',
  [MAKE_READY_STATUS.Blocked]: 'r',
};

export const HOUSEKEEPING_STATUS_PILL: Record<HousekeepingStatus, PillProps['tone']> = {
  [HOUSEKEEPING_STATUS.Pending]: 'r',
  [HOUSEKEEPING_STATUS.InProgress]: 'y',
  [HOUSEKEEPING_STATUS.Completed]: 'g',
  [HOUSEKEEPING_STATUS.Skipped]: 'b',
};

export const TICKET_PRIORITY_PILL: Record<TicketPriority, PillProps['tone']> = {
  [TICKET_PRIORITY.Urgent]: 'r',
  [TICKET_PRIORITY.High]: 'y',
  [TICKET_PRIORITY.Medium]: 'b',
  [TICKET_PRIORITY.Low]: 'b',
};

// --- select option lists -------------------------------------------------

const toOptions = (labels: Record<string, string>): readonly EntitySelectOption[] =>
  Object.entries(labels).map(([value, label]) => ({ value, label }));

export const APARTMENT_STATUS_OPTIONS = toOptions(APARTMENT_STATUS_LABELS);
export const MAINTENANCE_STATUS_OPTIONS = toOptions(MAINTENANCE_STATUS_LABELS);
export const MAKE_READY_STATUS_OPTIONS = toOptions(MAKE_READY_STATUS_LABELS);
export const MAKE_READY_CATEGORY_OPTIONS = toOptions(MAKE_READY_CATEGORY_LABELS);
export const HOUSEKEEPING_STATUS_OPTIONS = toOptions(HOUSEKEEPING_STATUS_LABELS);
export const TICKET_PRIORITY_OPTIONS = toOptions(TICKET_PRIORITY_LABELS);

// --- form field descriptors ---------------------------------------------

export const MAINTENANCE_FIELDS: ReadonlyArray<EntityField<MaintenanceFormValues>> = [
  { name: 'issue', label: 'Issue', full: true, placeholder: 'Bathroom faucet dripping' },
  { name: 'ticketNumber', label: 'Ticket #', placeholder: 'M-006' },
  { name: 'priority', label: 'Priority', type: 'select', options: TICKET_PRIORITY_OPTIONS },
  { name: 'status', label: 'Status', type: 'select', options: MAINTENANCE_STATUS_OPTIONS },
  { name: 'reporterName', label: 'Reported by', placeholder: 'Unit 101 · Earl Davis' },
  { name: 'resolution', label: 'Resolution', type: 'textarea', full: true, placeholder: 'How it was resolved…' },
];

export const HOUSEKEEPING_FIELDS: ReadonlyArray<EntityField<HousekeepingFormValues>> = [
  { name: 'taskType', label: 'Task', full: true, placeholder: 'Unit 103 Make-Ready Deep Clean' },
  { name: 'area', label: 'Unit / area', placeholder: '103, Common, Dining…' },
  { name: 'status', label: 'Status', type: 'select', options: HOUSEKEEPING_STATUS_OPTIONS },
  { name: 'dueDate', label: 'Due date', type: 'date' },
];
