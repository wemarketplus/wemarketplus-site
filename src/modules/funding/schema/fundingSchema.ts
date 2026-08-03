import { z } from 'zod';
import { FUNDING_STATUS } from '../constants/fundingConstants';

// Create/edit funding form — mirrors CreateFundingDto / UpdateFundingDto
// (wemarketplus-backend/src/funding/dto). `opportunityName` and `sourceUrl` are
// required on create; everything else is optional and stripped when blank.
// Note: the backend UPDATE whitelist is narrower than create — it does NOT accept
const statusValues = Object.values(FUNDING_STATUS) as [string, ...string[]];

// number inputs registered with valueAsNumber yield NaN when blank. z.number()
// rejects NaN before any .refine runs, so a blank optional number would fail
// the whole form; coerce NaN -> undefined via .or(z.nan()) so it validates as
// "unset" (optNum then drops it before send). A real value below zero still
// fails min(0).
const optionalNonNegativeNumber = z
  .number()
  .min(0, 'Must be zero or more')
  .optional()
  .or(z.nan().transform(() => undefined));

export const fundingSchema = z.object({
  opportunityName: z.string().min(1, 'Opportunity name is required').max(255),
  sourceUrl: z.string().min(1, 'Source URL is required').max(2048),
  status: z.enum(statusValues).optional().or(z.literal('')),
  programType: z.string().max(255).optional(),
  maxAwardPerEin: optionalNonNegativeNumber,
  applicationDeadline: z.string().optional(),
  applicationLink: z
    .string()
    .url('Enter a valid URL')
    .max(2048)
    .optional()
    .or(z.literal('')),
  notes: z.string().optional(),
});

export type FundingFormValues = z.infer<typeof fundingSchema>;
