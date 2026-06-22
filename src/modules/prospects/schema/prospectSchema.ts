import { z } from 'zod';
import { ProspectStatus, Urgency } from '@/shared/types';
import { ProspectStage, ProspectUrgency } from '../types/prospectsTypes';

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
