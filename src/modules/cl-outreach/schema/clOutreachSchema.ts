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
  /**
   * Captured coordinates. Held as STRINGS because every other value on this form
   * is one (react-hook-form reads inputs as strings) and the mapper already
   * converts on the way out — a lone number field here would be the only value
   * whose empty state is `undefined` rather than `''`, which is how a "clear the
   * GPS" edit ends up sending `NaN`.
   *
   * Not user-typed: set by the Capture GPS button via setValue, and validated only
   * loosely for that reason. The DTO is the real gate (numeric, 7 decimal places).
   */
  gpsLat: z.string().optional().or(z.literal('')),
  gpsLng: z.string().optional().or(z.literal('')),
});

export type VisitFormValues = z.infer<typeof visitSchema>;
