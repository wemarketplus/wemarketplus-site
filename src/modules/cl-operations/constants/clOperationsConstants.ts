import type { PillProps } from '@/shared/ui/data-display';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import {
  type Role,
  CL_INVENTORY_ROLES,
  CL_MAKE_READY_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_HOUSEKEEPING_ROLES,
  CL_UNIT_STATUS_ROLES,
  CL_MAINTENANCE_VIEW_ROLES,
} from '@/shared/rbac';
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

// `allow` mirrors this view's route-level role guard in router.tsx — the
// in-page tab nav (OperationsViewNav) filters against it so a role never sees
// a tab for a sub-view it can't actually navigate into.
export const OPERATIONS_VIEWS: ReadonlyArray<{
  value: ClOperationsUiState['view'];
  label: string;
  allow: readonly Role[];
}> = [
  { value: 'communities', label: 'Communities', allow: CL_INVENTORY_ROLES },
  { value: 'inventory', label: 'Apartments', allow: CL_INVENTORY_ROLES },
  { value: 'make-ready', label: 'Make-ready', allow: CL_MAKE_READY_ROLES },
  // Same board, housekeeping category only. CL_HOUSEKEEPING_ROLES rather than
  // CL_MAKE_READY_ROLES: a Maintenance tech has the full board and the cleaning
  // slice is not theirs to work, so a tab for it would be noise.
  { value: 'make-ready-clean', label: 'Make-Ready Clean', allow: CL_HOUSEKEEPING_ROLES },
  { value: 'maintenance', label: 'Maintenance', allow: CL_MAINTENANCE_ROLES },
  { value: 'housekeeping', label: 'Housekeeping', allow: CL_HOUSEKEEPING_ROLES },
  { value: 'unit-status', label: 'Unit Status', allow: CL_UNIT_STATUS_ROLES },
  { value: 'maintenance-view', label: 'Maintenance View', allow: CL_MAINTENANCE_VIEW_ROLES },
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
  [APARTMENT_STATUS.Waitlisted]: 'Waitlisted',
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

// Full words for all four — see the note on cl-tasks' PRIORITY_LABELS, which is
// the same map spelled twice. This copy has the same defect for the same reason:
// TICKET_PRIORITY_OPTIONS below is derived from it and feeds the maintenance
// ticket form's Priority dropdown, so the clipped "Med" was truncating an option
// label here too, not just a table pill.
export const TICKET_PRIORITY_LABELS: Record<TicketPriority, string> = {
  [TICKET_PRIORITY.Urgent]: 'Urgent',
  [TICKET_PRIORITY.High]: 'High',
  [TICKET_PRIORITY.Medium]: 'Medium',
  [TICKET_PRIORITY.Low]: 'Low',
};

// --- pill tones ----------------------------------------------------------

export const APARTMENT_STATUS_PILL: Record<ApartmentStatus, PillProps['tone']> = {
  [APARTMENT_STATUS.Available]: 'g',
  [APARTMENT_STATUS.Occupied]: 'b',
  [APARTMENT_STATUS.Reserved]: 'p',
  // Same tone family as Reserved: both mean "not available, and not because
  // something is wrong with the unit".
  [APARTMENT_STATUS.Waitlisted]: 'p',
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
  // `lookup` — options come from the live staff list at render time, same as
  // housekeeping's. This is what puts a ticket on a technician's My Queue.
  { name: 'assignedTo', label: 'Assigned to', type: 'lookup' },
  { name: 'reporterName', label: 'Reported by', placeholder: 'Unit 101 · Earl Davis' },
  { name: 'resolution', label: 'Resolution', type: 'textarea', full: true, placeholder: 'How it was resolved…' },
];

export const HOUSEKEEPING_FIELDS: ReadonlyArray<EntityField<HousekeepingFormValues>> = [
  { name: 'taskType', label: 'Task', full: true, placeholder: 'Unit 103 Make-Ready Deep Clean' },
  { name: 'area', label: 'Unit / area', placeholder: '103, Common, Dining…' },
  { name: 'status', label: 'Status', type: 'select', options: HOUSEKEEPING_STATUS_OPTIONS },
  // `lookup`, so the options come from the live staff list at render time — see
  // EntityField's note on why a record reference is never a free-text field.
  { name: 'assignedTo', label: 'Assigned to', type: 'lookup' },
  /**
   * `min` greys out every day before today in the picker — the same shared
   * mechanism the reminder, task and lead follow-up dates use (see
   * tasksConstants TASK_FIELDS), rather than a private rule for this form.
   *
   * Passed as the FUNCTION, not `todayLocalDate()`: a module-load value would
   * freeze "today" for the life of the tab, so a form left open across midnight
   * would still offer yesterday.
   *
   * The picker is the first of three layers — a keyboard user can still TYPE a
   * past date, so HousekeepingFormModal re-checks on submit and
   * CreateClHousekeepingTaskDto enforces it server-side (@IsNotPastDate).
   */
  { name: 'dueDate', label: 'Due date', type: 'date', min: todayLocalDate },
];
