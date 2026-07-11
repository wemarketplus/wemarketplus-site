import { z } from 'zod';
import { REFERRAL_TYPE_LABELS } from '../constants/clReferralsConstants';

// Add/edit form for a CommunityLink referral source. Mirrors the backend
// CreateClReferralSourceDto: only name is required; the rest are optional.
const typeValues = Object.keys(REFERRAL_TYPE_LABELS) as [string, ...string[]];

export const referralSchema = z.object({
  name: z.string().min(1, 'Required').max(200),
  organization: z.string().max(200).optional().or(z.literal('')),
  type: z.enum(typeValues),
  phone: z.string().max(200).optional().or(z.literal('')),
  email: z.string().email('Enter a valid email').optional().or(z.literal('')),
  address: z.string().max(200).optional().or(z.literal('')),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type ReferralFormValues = z.infer<typeof referralSchema>;
