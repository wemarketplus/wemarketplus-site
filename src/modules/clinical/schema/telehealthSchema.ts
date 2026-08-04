import { z } from 'zod';
import { TELEHEALTH_STATUS } from '../constants/clinicalStatus';

// Create/edit form for a telehealth session. Mirrors the backend
// CreateTelehealthSessionDto: patientName + scheduledAt are required, the rest
// optional. scheduledAt is a `datetime-local` value (local wall clock) because
// the backend column is a timestamptz — a date-only input would pin every
// session to midnight.
const statusValues = Object.values(TELEHEALTH_STATUS) as [string, ...string[]];

// durationMin renders as a number input, so react-hook-form hands us a number —
// or NaN when the box is empty, which is what the nan() branch absorbs. It must
// NOT be a string schema: valueAsNumber means a string never arrives.
const optionalNonNegativeNumber = z
  .number()
  .min(0, 'Must be zero or more')
  .optional()
  .or(z.nan().transform(() => undefined));

export const telehealthSchema = z.object({
  patientName: z.string().min(1, 'Required').max(200),
  providerName: z.string().max(200).optional().or(z.literal('')),
  sessionType: z.string().max(200).optional().or(z.literal('')),
  scheduledAt: z.string().min(1, 'Required'),
  durationMin: optionalNonNegativeNumber,
  status: z.enum(statusValues),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type TelehealthFormValues = z.infer<typeof telehealthSchema>;
