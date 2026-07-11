import { z } from 'zod';
import { TaskPriority, TaskStatus } from '../types/activityTypes';

// Create/edit form for a task (surfaced as a reminder). Mirrors the backend
// CreateTaskDto (wemarketplus-backend/src/tasks/dto/create-task.dto.ts): only
// title is required. prospectId/assignedTo are UUIDs the reminders view does not
// collect, so they are omitted from the form and left untouched.
const priorityValues = Object.values(TaskPriority) as [string, ...string[]];
const statusValues = Object.values(TaskStatus) as [string, ...string[]];

export const taskSchema = z.object({
  title: z.string().min(1, 'Title is required').max(200),
  description: z.string().max(2000).optional().or(z.literal('')),
  dueDate: z.string().optional().or(z.literal('')),
  priority: z.enum(priorityValues),
  status: z.enum(statusValues),
});

export type TaskFormValues = z.infer<typeof taskSchema>;
