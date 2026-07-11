import { z } from 'zod';
import { BED_UNIT_STATUS } from '../constants/clinicalStatus';

// Create/edit form for a bed unit. Mirrors the backend CreateBedUnitDto
// (wemarketplus-backend bed-units): only facilityName is required.
const statusValues = Object.values(BED_UNIT_STATUS) as [string, ...string[]];

export const bedUnitSchema = z.object({
  facilityName: z.string().min(1, 'Required').max(200),
  bedType: z.string().max(200).optional().or(z.literal('')),
  status: z.enum(statusValues),
  patientName: z.string().max(200).optional().or(z.literal('')),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type BedUnitFormValues = z.infer<typeof bedUnitSchema>;
