import { z } from 'zod';
import { CL_TASK_STATUS, TICKET_PRIORITY } from '@/modules/cl-outreach';

// Create/edit form for a CommunityLink task. Mirrors the backend
// CreateClTaskDto: only title is required; everything else is optional.
const priorityValues = Object.values(TICKET_PRIORITY) as [string, ...string[]];
const statusValues = Object.values(CL_TASK_STATUS) as [string, ...string[]];

export const taskSchema = z.object({
  title: z.string().min(1, 'Required').max(400),
  priority: z.enum(priorityValues),
  status: z.enum(statusValues),
  // Who owes the task. The column, the index and the DTO have always accepted it
  // and the care dashboard counts on it, but no form collected it — so "Check
  // Tasks for anything else assigned to you" pointed at a list where nothing was
  // ever assigned to anyone.
  assignedTo: z.string().optional().or(z.literal('')),
  dueDate: z.string().optional().or(z.literal('')),
  description: z.string().max(2000).optional().or(z.literal('')),
});

export type TaskFormValues = z.infer<typeof taskSchema>;
