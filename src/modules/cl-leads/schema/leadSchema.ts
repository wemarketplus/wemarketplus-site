import { z } from 'zod';
import { CareLevel, LeadStatus, Urgency } from '@/shared/types';

// Add Lead form — mirrors the modal in communitylinkmax-demo.html.
export const newLeadSchema = z.object({
  name: z.string().min(2, 'Required').max(120),
  careType: z.enum([CareLevel.IL, CareLevel.AL, CareLevel.MC]),
  status: z.enum([
    LeadStatus.Inquiry,
    LeadStatus.TourScheduled,
    LeadStatus.Proposal,
    LeadStatus.FollowUp,
    LeadStatus.MoveIn,
    LeadStatus.Lost,
  ]),
  urgency: z.enum([Urgency.Hot, Urgency.Warm, Urgency.Cold]),
  source: z.string().min(1, 'Required').max(120),
  followUpDate: z.string().min(1, 'Pick a date'),
  phone: z.string().min(7, 'Enter a phone').max(40),
  email: z.string().email('Enter a valid email'),
  notes: z.string().max(1000).optional(),
});

export type NewLeadFormValues = z.infer<typeof newLeadSchema>;
