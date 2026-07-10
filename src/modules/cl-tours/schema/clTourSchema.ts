import { z } from 'zod';
import { CL_TOUR_STATUS } from '../constants/clToursApiConstants';

// Book-tour form — mirrors POST /cl/tours (CreateClTourRequest). scheduledAt is
// the only field the backend requires; it comes from a datetime-local input.
export const newTourSchema = z.object({
  scheduledAt: z.string().min(1, 'Pick a date and time'),
  status: z.enum([
    CL_TOUR_STATUS.Scheduled,
    CL_TOUR_STATUS.Completed,
    CL_TOUR_STATUS.Cancelled,
    CL_TOUR_STATUS.NoShow,
  ]),
  // Kept as a string to match the <input type="number"> register value; the
  // hook parses it to a number before sending. Empty string means "unset".
  durationMin: z
    .string()
    .optional()
    .refine((v) => !v || (/^\d+$/.test(v) && Number(v) <= 600), 'Enter 0–600 minutes'),
  notes: z.string().max(1000).optional(),
});

export type NewTourFormValues = z.infer<typeof newTourSchema>;
