import { z } from 'zod';
import { TERRITORY_PRIORITY } from '../constants/territoriesConstants';

// Create/edit territory form — mirrors CreateTerritoryDto / UpdateTerritoryDto
// (wemarketplus-backend/src/territories/dto). `name` is required; the rest are
// optional and stripped when blank. `zipCodes` is a string[] on the backend; the
// form edits it as a comma/space-separated text field (parsed in the mapper).
const priorityValues = Object.values(TERRITORY_PRIORITY) as [string, ...string[]];

export const territorySchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  city: z.string().max(100).optional(),
  state: z.string().max(100).optional(),
  // Free text: comma or whitespace separated zip codes; parsed into string[].
  zipCodes: z.string().optional(),
  assignedTo: z.string().uuid('Assigned-to must be a valid user UUID').optional().or(z.literal('')),
  priority: z.enum(priorityValues).optional().or(z.literal('')),
  notes: z.string().optional(),
});

export type TerritoryFormValues = z.infer<typeof territorySchema>;
