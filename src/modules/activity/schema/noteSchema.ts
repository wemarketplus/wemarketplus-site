import { z } from 'zod';
import { Urgency } from '@/shared/types';

// Create/edit form for a structured prospect note. Mirrors the backend
// CreateNoteDto (wemarketplus-backend/src/notes/dto/create-note.dto.ts): only
// prospectId (UUID) + summary are required; everything else is optional. blank
// optionals are dropped before the request so the DTO never sees empty strings.
export const noteSchema = z.object({
  prospectId: z.string().min(1, 'Prospect id is required').max(200),
  summary: z.string().min(1, 'Add a short summary').max(2000),
  contactType: z.string().max(200).optional().or(z.literal('')),
  urgency: z.enum([Urgency.Hot, Urgency.Warm, Urgency.Cold]),
  patientStatus: z.string().max(200).optional().or(z.literal('')),
  barriers: z.string().max(2000).optional().or(z.literal('')),
  nextStep: z.string().max(500).optional().or(z.literal('')),
  followUpDate: z.string().optional().or(z.literal('')),
});

export type NoteFormValues = z.infer<typeof noteSchema>;
