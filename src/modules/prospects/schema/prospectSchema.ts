import { z } from 'zod';
import { ProspectStatus, Urgency } from '@/shared/types';

export const prospectSchema = z.object({
  name: z.string().min(2, 'Required').max(200),
  email: z.string().email('Enter a valid email address'),
  phone: z.string().min(7).max(40),
  referralSource: z.string().min(2).max(200),
  assignedMarketer: z.string().min(2).max(120),
  status: z.enum([
    ProspectStatus.Inquiry,
    ProspectStatus.PendingAdmission,
    ProspectStatus.Admitted,
    ProspectStatus.Lost,
  ]),
  urgency: z.enum([Urgency.Hot, Urgency.Warm, Urgency.Cold]),
  nextStep: z.string().min(2).max(500),
  followUpDate: z.string(),
});

export type ProspectFormValues = z.infer<typeof prospectSchema>;
