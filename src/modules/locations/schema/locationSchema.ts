import { z } from 'zod';
import { LOCATION_STATUS } from '../constants/locationsConstants';

// Create/edit location form — mirrors CreateLocationDto / UpdateLocationDto
// (wemarketplus-backend/src/locations/dto). `locationName` is required; the rest
// are optional and stripped when blank. companyId is IsUUID gated and set
// only at creation (the backend UPDATE whitelist excludes them — see the mapper).
const statusValues = Object.values(LOCATION_STATUS) as [string, ...string[]];

export const locationSchema = z.object({
  locationName: z.string().min(1, 'Location name is required').max(255),
  state: z.string().max(255).optional(),
  county: z.string().max(255).optional(),
  city: z.string().max(255).optional(),
  status: z.enum(statusValues).optional().or(z.literal('')),
  // Registered with valueAsNumber, which yields NaN on empty input; coerce NaN ->
  // undefined so an omitted count validates as optional. Input and output are both
  // number|undefined, avoiding the RHF Resolver mismatch (see companies schema).
  employeeCount: z
    .number({ error: 'Enter a number' })
    .int('Must be a whole number')
    .min(0, 'Must be zero or more')
    .optional()
    .or(z.nan().transform(() => undefined)),
  companyId: z.string().uuid('Company id must be a valid UUID').optional().or(z.literal('')),
  address: z.string().optional(),
  notes: z.string().optional(),
});

export type LocationFormValues = z.infer<typeof locationSchema>;
