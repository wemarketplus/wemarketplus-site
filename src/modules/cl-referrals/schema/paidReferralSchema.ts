import { z } from 'zod';
import { CL_CARE_LEVEL, CL_URGENCY, FEE_STATUS } from '../constants/clReferralsApiConstants';

const careValues = Object.values(CL_CARE_LEVEL) as [string, ...string[]];
const urgencyValues = Object.values(CL_URGENCY) as [string, ...string[]];
const feeValues = Object.values(FEE_STATUS) as [string, ...string[]];

// Paid-referral form — mirrors POST /cl/paid-referrals. prospectName + sourceName
// are the only required fields.
export const paidReferralSchema = z.object({
  prospectName: z.string().min(1, 'Required').max(200),
  prospectPhone: z.string().max(200).optional().or(z.literal('')),
  careLevel: z.enum(careValues),
  urgency: z.enum(urgencyValues),
  sourceName: z.string().min(1, 'Required').max(200),
  referralFee: z
    .string()
    .optional()
    .or(z.literal(''))
    .refine((v) => !v || /^\d+(\.\d{1,2})?$/.test(v), 'Enter an amount like 3500'),
  feeStatus: z.enum(feeValues),
  stage: z.string().max(100).optional().or(z.literal('')),
});

export type PaidReferralFormValues = z.infer<typeof paidReferralSchema>;
