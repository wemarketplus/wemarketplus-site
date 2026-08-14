import { opt } from '@/shared/ui/entity';
import type {
  ClTaskRecord,
  ClTaskStatus,
  CreateClTaskRequest,
  TicketPriority,
} from '@/modules/cl-outreach';
import type { TaskFormValues } from '../schema/taskSchema';

// Form values -> POST /cl/tasks body. Drops blank optionals so the DTO's
// validation never sees an empty string.
export function toCreateTask(values: TaskFormValues): CreateClTaskRequest {
  return {
    title: values.title.trim(),
    priority: values.priority as TicketPriority,
    status: values.status as ClTaskStatus,
    // Blank omitted rather than sent as '': assignedTo is @IsUUID() on the DTO.
    ...opt('assignedTo', values.assignedTo),
    ...opt('dueDate', values.dueDate),
    ...opt('description', values.description),
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
