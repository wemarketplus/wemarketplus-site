import { z } from 'zod';
import { WIB_STATUS } from '../constants/wibsConstants';

// Create/edit WIB form — mirrors CreateWibDto / UpdateWibDto
// (wemarketplus-backend/src/wibs/dto). `wibName` + `sourceUrl` are required on
// create; the rest are optional and stripped when blank. Territory assignment is
// a dedicated endpoint (PUT /wibs/:id/territory) and is intentionally not part of
// this form.
const statusValues = Object.values(WIB_STATUS) as [string, ...string[]];

const optionalNonNegativeNumber = z
  .number()
  .min(0, 'Must be zero or more')
  .optional()
  .or(z.nan().transform(() => undefined));

export const wibSchema = z.object({
  wibName: z.string().min(2, 'WIB name is required').max(255),
  sourceUrl: z.string().min(1, 'Source URL is required').max(2048),
  shortName: z.string().max(100).optional(),
  state: z.string().max(100).optional(),
  status: z.enum(statusValues).optional().or(z.literal('')),
  wibPhone: z.string().max(50).optional(),
  wibEmail: z.string().email('Enter a valid email').max(255).optional().or(z.literal('')),
  website: z.string().url('Enter a valid URL').max(2048).optional().or(z.literal('')),
  maxAwardPerEin: optionalNonNegativeNumber,
  matchRequirementPct: optionalNonNegativeNumber,
  wibType: z.string().max(255).optional(),
  nextSteps: z.string().optional(),
  blockers: z.string().optional(),
  notes: z.string().optional(),
});

export type WibFormValues = z.infer<typeof wibSchema>;
