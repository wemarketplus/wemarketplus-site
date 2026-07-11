import { z } from 'zod';

// Log/edit outreach-visit form — mirrors POST /cl/outreach-visits. visitDate is
// the only required field (a date input).
export const visitSchema = z.object({
  visitDate: z.string().min(1, 'Pick a date'),
  contactName: z.string().max(200).optional().or(z.literal('')),
  locationName: z.string().max(200).optional().or(z.literal('')),
  visitType: z.string().max(200).optional().or(z.literal('')),
  miles: z
    .string()
    .optional()
    .or(z.literal(''))
    .refine((v) => !v || /^\d+(\.\d)?$/.test(v), 'Enter miles like 12.5'),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type VisitFormValues = z.infer<typeof visitSchema>;
