import { z } from 'zod';
import { JobPriority, JobType } from '../types/jobsTypes';

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/** Hand-created job against an existing pipeline. */
export const newJobSchema = z.object({
  jobType: z.enum(Object.values(JobType) as [string, ...string[]]),
  pipelineId: z.string().uuid('Pick a pipeline'),
  priority: z.enum(Object.values(JobPriority) as [string, ...string[]]),
  dueDate: z
    .string()
    .regex(ISO_DATE, 'Use YYYY-MM-DD')
    .optional()
    .or(z.literal('')),
  objective: z.string().trim().max(2000).optional().or(z.literal('')),
});

export type NewJobFormValues = z.infer<typeof newJobSchema>;
