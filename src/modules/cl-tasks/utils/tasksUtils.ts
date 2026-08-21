import { optOrNull } from '@/shared/ui/entity';
import type {
  ClTaskRecord,
  ClTaskStatus,
  CreateClTaskRequest,
  TicketPriority,
} from '@/modules/cl-outreach';
import type { TaskFormValues } from '../schema/taskSchema';

/**
 * Form values -> POST /cl/tasks body (and the PATCH body, via toUpdateTask).
 *
 * `optOrNull`, NOT `opt`, for all three nullable fields. `opt` OMITS a blank
 * key, and an omitted key in a PATCH means "leave unchanged" — so clearing
 * Assigned to and saving sent no `assignedTo` at all and the task came back
 * still assigned to the same person. Verified against the API: the same PATCH
 * with the key omitted keeps the old assignee, and with `assignedTo: null`
 * clears the column.
 *
 * Safe for exactly these three because each is `nullable: true` on ClTask, and
 * each DTO field is `@IsOptional()` — which skips validation on null, so
 * @IsUUID / @Matches(ISO_DATE) never see it. `title`, `priority` and `status`
 * stay unconditional: they are NOT NULL, and a null would violate the column
 * rather than clear it. See the "Clearable optionals" note in
 * shared/ui/entity/formValues.ts.
 */
export function toCreateTask(values: TaskFormValues): CreateClTaskRequest {
  return {
    title: values.title.trim(),
    priority: values.priority as TicketPriority,
    status: values.status as ClTaskStatus,
    ...optOrNull('assignedTo', values.assignedTo),
    ...optOrNull('dueDate', values.dueDate),
    ...optOrNull('description', values.description),
  };
}

// PATCH body is the same partial shape; the backend accepts any subset.
export function toUpdateTask(values: TaskFormValues): Partial<CreateClTaskRequest> {
  return toCreateTask(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toTaskFormValues(task: ClTaskRecord): TaskFormValues {
  return {
    title: task.title,
    priority: task.priority,
    status: task.status,
    assignedTo: task.assignedTo ?? '',
    dueDate: task.dueDate ?? '',
    description: task.description ?? '',
  };
}
