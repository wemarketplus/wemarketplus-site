import { z } from 'zod';
import { ProspectStage, ProspectUrgency } from '@/modules/prospects/types/prospectsTypes';

// Create-opportunity form — the Pipeline board's only creation path (Outreach
// rows, unlike Referral-to-admit prospects, have no other screen that makes
// one). Mirrors the POST /prospects body (CreateProspectRequest); `name` is
// the only field the backend requires.
export const newOpportunitySchema = z.object({
  name: z.string().min(1, 'Opportunity name is required').max(200),
  facilityName: z.string().max(200).optional(),
  stage: z.nativeEnum(ProspectStage),
  urgency: z.nativeEnum(ProspectUrgency),
  notes: z.string().max(1000).optional(),
});

export type NewOpportunityFormValues = z.infer<typeof newOpportunitySchema>;
