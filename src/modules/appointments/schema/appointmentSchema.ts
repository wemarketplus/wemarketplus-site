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
  })
  .refine((values) => new Date(values.endAt) > new Date(values.startAt), {
    message: 'End must be after start',
    path: ['endAt'],
  });

export type NewAppointmentFormValues = z.infer<typeof newAppointmentSchema>;
