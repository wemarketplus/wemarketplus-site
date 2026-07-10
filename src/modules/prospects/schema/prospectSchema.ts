import { z } from 'zod';
import { ProspectStage, ProspectUrgency } from '../types/prospectsTypes';

// Create-prospect form — mirrors the POST /prospects body
// (CreateProspectRequest). patientName is the only field the backend requires;
// stage/urgency carry sensible defaults so the row lands in the pipeline.
export const newProspectSchema = z.object({
  patientName: z.string().min(1, 'Patient name is required').max(200),
  facilityName: z.string().max(200).optional(),
  stage: z.nativeEnum(ProspectStage),
  urgency: z.nativeEnum(ProspectUrgency),
  referringPhysician: z.string().max(200).optional(),
  diagnosis: z.string().max(500).optional(),
  phone: z.string().max(40).optional(),
  notes: z.string().max(1000).optional(),
});

export type NewProspectFormValues = z.infer<typeof newProspectSchema>;
