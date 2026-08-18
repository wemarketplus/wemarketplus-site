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
  /**
   * Where the tour starts and ends, each a label plus an optional pinned point.
   *
   * SIX FLAT FIELDS rather than two nested objects, matching the appointment
   * form: they are the six keys the request carries, so the picker's value is
   * assembled with `toLocationValue` for display and split back out with
   * `fromLocationValue` on submit, and no mapper has to know a bespoke shape.
   *
   * All optional. A tour whose family is meeting the guide at the door has no
   * pickup point, and a tour booked before the picker existed has neither —
   * requiring them would make every historical row un-editable.
   *
   * The coordinates are NOT validated as a pair here: the picker only ever sets
   * both or clears both, and the server enforces the pairing regardless. A zod
   * refinement would only fire on a state the UI cannot produce.
   */
  fromLocation: z.string().trim().max(200).optional().or(z.literal('')),
  fromLat: z.number().optional(),
  fromLng: z.number().optional(),
  toLocation: z.string().trim().max(200).optional().or(z.literal('')),
  toLat: z.number().optional(),
  toLng: z.number().optional(),
  outcome: z.string().max(200).optional().or(z.literal('')),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type TourFormValues = z.infer<typeof tourSchema>;
