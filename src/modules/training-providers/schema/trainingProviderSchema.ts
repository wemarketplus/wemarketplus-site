import { z } from 'zod';
import { TRAINING_PROVIDER_STATUS } from '../constants/trainingConstants';

// Create/edit training-provider form — mirrors CreateTrainingProviderDto /
// UpdateTrainingProviderDto (wemarketplus-backend/src/training-providers/dto).
// `name` is required; the rest are optional and stripped when blank. contactEmail
// is IsEmail gated (validated only when present).
const statusValues = Object.values(TRAINING_PROVIDER_STATUS) as [string, ...string[]];

export const trainingProviderSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  providerType: z.string().max(255).optional(),
  website: z.string().max(255).optional(),
  contactEmail: z.string().email('Enter a valid email').max(255).optional().or(z.literal('')),
  contactPhone: z.string().max(50).optional(),
  programs: z.string().optional(),
  state: z.string().max(255).optional(),
  status: z.enum(statusValues).optional().or(z.literal('')),
  notes: z.string().optional(),
});

export type TrainingProviderFormValues = z.infer<typeof trainingProviderSchema>;
