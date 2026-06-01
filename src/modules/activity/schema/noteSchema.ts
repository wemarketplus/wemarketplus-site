import { z } from 'zod';
import { Urgency } from '@/shared/types';

// Mirrors the structured note form on wemarketplus-site/notes.
export const noteSchema = z.object({
  prospectId: z.string().min(1, 'Pick a prospect'),
  interactionType: z.string().min(1).max(80),
  contactType: z.string().min(1).max(80),
  urgency: z.enum([Urgency.Hot, Urgency.Warm, Urgency.Cold]),
  summary: z.string().min(5, 'Add a short summary').max(2000),
  patientStatus: z.string().max(500).optional(),
  barriers: z.string().max(500).optional(),
  nextStep: z.string().min(2, 'Next step required').max(500),
  followUpDate: z.string(),
});

export type NoteFormValues = z.infer<typeof noteSchema>;
