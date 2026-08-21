import { z } from 'zod';
import { AppointmentType } from '../types/appointmentsTypes';

/**
 * New appointment. The backend also enforces endAt > startAt; this mirrors it so the
 * user gets the error before a round trip.
 */
export const newAppointmentSchema = z
  .object({
    jobId: z.string().uuid('Pick a job'),
    title: z.string().trim().min(1, 'Title is required').max(300),
    startAt: z.string().min(1, 'Start is required'),
    endAt: z.string().min(1, 'End is required'),
    appointmentType: z.enum(
      Object.values(AppointmentType) as [string, ...string[]],
    ),
    location: z.string().trim().max(300).optional().or(z.literal('')),
    /**
     * Coordinates for `location`, written by the map picker. Optional and
     * PAIRED — the server rejects a lone half — and deliberately absent for a
     * virtual or phone appointment, whose "location" is a meeting link or a
     * number rather than a place.
     */
    locationLat: z.number().optional(),
    locationLng: z.number().optional(),
    /**
     * Who the appointment belongs to. Blank means the signed-in user — the server
     * defaults `assignedRep` to the caller — so `''` is a valid value here and is
     * stripped rather than sent, which is why this is not `.uuid()` outright.
     */
    assignedRep: z
      .string()
      .uuid('Pick a person to assign this to')
      .optional()
      .or(z.literal('')),
  })
  .refine((values) => new Date(values.endAt) > new Date(values.startAt), {
    message: 'End must be after start',
    path: ['endAt'],
  });

export type NewAppointmentFormValues = z.infer<typeof newAppointmentSchema>;
