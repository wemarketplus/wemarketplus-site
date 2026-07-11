import { z } from 'zod';
import { CL_CARE_LEVEL, CL_LEAD_STAGE, CL_URGENCY } from '../constants/clLeadApiConstants';

// Create/edit form for a CommunityLink lead. Mirrors the backend
// CreateClLeadDto (wemarketplus-backend/src/communitylink/dto/cl-lead.dto.ts):
// only firstName is required; everything else is optional. The UI collects a
// single "Full name" and splits it into firstName/lastName on submit.
const stageValues = Object.values(CL_LEAD_STAGE) as [string, ...string[]];
const careValues = Object.values(CL_CARE_LEVEL) as [string, ...string[]];
const urgencyValues = Object.values(CL_URGENCY) as [string, ...string[]];

export const leadSchema = z.object({
  fullName: z.string().min(1, 'Required').max(400),
  phone: z.string().max(200).optional().or(z.literal('')),
  email: z.string().email('Enter a valid email').optional().or(z.literal('')),
  careLevel: z.enum(careValues),
  stage: z.enum(stageValues),
  urgency: z.enum(urgencyValues),
  source: z.string().max(200).optional().or(z.literal('')),
  followUpDate: z.string().optional().or(z.literal('')),
  notes: z.string().max(2000).optional().or(z.literal('')),
});

export type LeadFormValues = z.infer<typeof leadSchema>;
