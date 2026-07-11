import { z } from 'zod';
import { TELEHEALTH_STATUS } from '../constants/clinicalStatus';

// Create/edit form for a telehealth session. Mirrors the backend
// CreateTelehealthSessionDto: patientName + scheduledAt are required, the rest
// optional. durationMin is a free-text numeric field (kept as a string in the
// form and coerced on submit).
const statusValues = Object.values(TELEHEALTH_STATUS) as [string, ...string[]];

export const telehealthSchema = z.object({
  patientName: z.string().min(1, 'Required').max(200),
  providerName: z.string().max(200).optional().or(z.literal('')),
  sessionType: z.string().max(200).optional().or(z.literal('')),
  scheduledAt: z.string().min(1, 'Required'),
  durationMin: z
    .string()
    .optional()
    .or(z.literal(''))
    .refine((v) => !v || (!Number.isNaN(Number(v)) && Number(v) >= 0), 'Enter a valid number'),
  status: z.enum(statusValues),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type TelehealthFormValues = z.infer<typeof telehealthSchema>;
