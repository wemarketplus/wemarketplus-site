import { z } from 'zod';
import { CL_TOUR_STATUS } from '../constants/clToursApiConstants';

// Book/edit-tour form — mirrors POST /cl/tours (CreateClTourRequest). scheduledAt
// is the only field the backend requires; it comes from a datetime-local input.
export const tourSchema = z.object({
  leadId: z.string().optional().or(z.literal('')),
  // Which staff member is giving the tour. The column and both DTOs have always
  // accepted it; the form never collected it, so every tour was unassigned and
  // the guide's "pick … which staff member is giving the tour" had no control.
  guideUserId: z.string().optional().or(z.literal('')),
  scheduledAt: z.string().min(1, 'Pick a date and time'),
  status: z.enum([
    CL_TOUR_STATUS.Scheduled,
    CL_TOUR_STATUS.Completed,
    CL_TOUR_STATUS.Cancelled,
    CL_TOUR_STATUS.NoShow,
  ]),
  durationMin: z.string().min(1, 'Pick a duration'),
  outcome: z.string().max(200).optional().or(z.literal('')),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type TourFormValues = z.infer<typeof tourSchema>;
