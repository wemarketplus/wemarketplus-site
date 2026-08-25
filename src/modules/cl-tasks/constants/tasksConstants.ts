import type { PillProps } from '@/shared/ui/data-display';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import {
  CL_TASK_STATUS,
  TICKET_PRIORITY,
  type ClTaskStatus,
  type TicketPriority,
} from '@/modules/cl-outreach';
import type { TaskFormValues } from '../schema/taskSchema';

export const CL_TASKS_PAGE_SIZE = 20;

// --- Display labels (backend enums -> human copy) --------------------------

/**
 * Full words for all four. "Med" was the odd one out — Urgent, High and Low
 * were spelled in full and only Medium was clipped, so the task form's Priority
 * dropdown offered "Urgent / High / Med / Low" and read as truncated text
 * rather than as a deliberate abbreviation. That is the QA report.
 *
 * These labels are NOT table-only: `PRIORITY_OPTIONS` below is derived from this
 * map and is what the create/edit form renders, so an abbreviation chosen to
 * keep a pill narrow was also shortening an option label, where there is no
 * width pressure at all. The old note here justified "Med" by the reference
 * demo — but the demo's own dropdown reads `<option value="Med">Medium</option>`,
 * i.e. it abbreviates the wire value and spells the label out, which is exactly
 * what this now does. "Medium" is also no wider than "Urgent", so the pills that
 * share this map gain nothing from the shorter string either.
 */
export const PRIORITY_LABELS: Record<TicketPriority, string> = {
  [TICKET_PRIORITY.Urgent]: 'Urgent',
  [TICKET_PRIORITY.High]: 'High',
  [TICKET_PRIORITY.Medium]: 'Medium',
  [TICKET_PRIORITY.Low]: 'Low',
};

export const STATUS_LABELS: Record<ClTaskStatus, string> = {
  [CL_TASK_STATUS.Open]: 'Open',
  [CL_TASK_STATUS.InProgress]: 'In progress',
  [CL_TASK_STATUS.Completed]: 'Completed',
  [CL_TASK_STATUS.Cancelled]: 'Cancelled',
};

export const PRIORITY_PILL: Record<TicketPriority, PillProps['tone']> = {
  [TICKET_PRIORITY.Urgent]: 'r',
  [TICKET_PRIORITY.High]: 'y',
  [TICKET_PRIORITY.Medium]: 'b',
  [TICKET_PRIORITY.Low]: 'p',
};

export const STATUS_PILL: Record<ClTaskStatus, PillProps['tone']> = {
  [CL_TASK_STATUS.Open]: 'b',
  [CL_TASK_STATUS.InProgress]: 'y',
  [CL_TASK_STATUS.Completed]: 'g',
  [CL_TASK_STATUS.Cancelled]: 'r',
};

// --- Select option lists (reused by the form + the filters) ----------------

const toOptions = (labels: Record<string, string>): readonly EntitySelectOption[] =>
  Object.entries(labels).map(([value, label]) => ({ value, label }));

export const PRIORITY_OPTIONS = toOptions(PRIORITY_LABELS);
export const STATUS_OPTIONS = toOptions(STATUS_LABELS);

// --- Create/edit form field descriptors (drive EntityFormModal) ------------

export const TASK_FIELDS: ReadonlyArray<EntityField<TaskFormValues>> = [
  // Required by taskSchema and by CreateClTaskDto; everything below is optional.
  { name: 'title', label: 'Title', required: true, full: true, placeholder: 'Follow up with family on tour' },
  { name: 'priority', label: 'Priority', type: 'select', options: PRIORITY_OPTIONS },
  { name: 'status', label: 'Status', type: 'select', options: STATUS_OPTIONS },
  // `lookup` — options come from the live staff list at render time.
  { name: 'assignedTo', label: 'Assigned to', type: 'lookup' },
  /**
   * `min` greys out every day before today in the picker itself — the same
   * shared mechanism the reminder form (activityConstants TASK_FIELDS) and the
   * lead follow-up date (leadsConstants LEAD_FIELDS) already use, rather than a
   * fourth private rule. Passed as the FUNCTION, not `todayLocalDate()`: a
   * module-load value would freeze "today" for the life of the tab, so a form
   * left open across midnight would still offer yesterday.
   *
   * The picker is only the first of three layers; a keyboard user can still type
   * a past date, so TaskFormModal re-checks on submit and CreateClTaskDto
   * enforces it server-side (@IsNotPastDate).
   */
  { name: 'dueDate', label: 'Due date', type: 'date', min: todayLocalDate },
  { name: 'description', label: 'Description', type: 'textarea', full: true, placeholder: 'Details, context, next steps…' },
];
