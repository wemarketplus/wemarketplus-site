import { z } from 'zod';
import { ReferralSourceStatus } from '@/shared/types';

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
