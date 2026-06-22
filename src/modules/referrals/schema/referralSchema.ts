import { z } from 'zod';
import { ReferralSourceStatus } from '@/shared/types';
import { ReferralSourceType } from '../types/referralsTypes';

export const referralSchema = z.object({
  fullName: z.string().min(2).max(200),
  title: z.string().min(2).max(120),
  organization: z.string().min(2).max(200),
  workPhone: z.string().min(7).max(40),
  cellPhone: z.string().max(40).optional(),
  email: z.string().email(),
  sourceType: z.string().min(2).max(80),
  status: z.enum([
    ReferralSourceStatus.Green,
    ReferralSourceStatus.Building,
    ReferralSourceStatus.Red,
  ]),
  trustLevel: z.number().int().min(1).max(5),
  priorityLevel: z.enum(['A', 'B', 'C']),
  territoryArea: z.string().max(120).optional(),
  acceptsGifts: z.boolean(),
});

export type ReferralFormValues = z.infer<typeof referralSchema>;

// Create-referral-source form — mirrors POST /referral-sources
// (CreateReferralSourceRequest). name is the only required field.
export const newReferralSchema = z.object({
  name: z.string().min(1, 'Name is required').max(200),
  type: z.nativeEnum(ReferralSourceType),
  contactName: z.string().max(200).optional(),
  phone: z.string().max(40).optional(),
  email: z.union([z.literal(''), z.string().email('Enter a valid email')]).optional(),
  city: z.string().max(120).optional(),
  state: z.string().max(120).optional(),
  notes: z.string().max(1000).optional(),
});

export type NewReferralFormValues = z.infer<typeof newReferralSchema>;
