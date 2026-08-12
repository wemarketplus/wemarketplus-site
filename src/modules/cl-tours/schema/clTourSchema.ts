import { z } from 'zod';
import { CL_TOUR_STATUS } from '../constants/clToursApiConstants';

// Book/edit-tour form — mirrors POST /cl/tours (CreateClTourRequest). scheduledAt
// is the only field the backend requires; it comes from a datetime-local input.
export const tourSchema = z.object({
  leadId: z.string().optional().or(z.literal('')),
  /**
   * Who is giving the tour. Optional, because an unassigned tour is a legitimate
   * "booked, host to be decided" state and the column is nullable.
   *
   * The field existed on ClTourRecord and on the POST body from the start but had
   * no input, so the guide's "pick the prospect, date, time, and which staff
   * member is giving the tour" named a control that was not there — and every
   * tour was written with a null host, which is also why the shared calendar had
   * no one to colour a tour row by.
   */
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
