import { z } from 'zod';

// TODO(backend): organization profile DTO. Today the backend is single-tenant
// without an Organization entity — when it ships, mirror the DTO and tighten
// constraints. Keeping a permissive shape so the page renders against
// fixtures.
export const organizationSchema = z.object({
  name: z.string().min(2, 'Required').max(200),
  city: z.string().min(1, 'Required').max(120),
  state: z.string().length(2, 'Pick a state'),
  phone: z.string().min(7).max(40),
});

export type OrganizationFormValues = z.infer<typeof organizationSchema>;
