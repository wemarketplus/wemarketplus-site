import { z } from 'zod';

// Mirrors the backend UpdateMyTenantDto (PATCH /tenants/me) profile subset.
// name maps to the tenant name (1..200 on the server); city/state/phone are the
// tenant contact fields.
export const organizationSchema = z.object({
  name: z.string().min(2, 'Required').max(200),
  city: z.string().min(1, 'Required').max(120),
  state: z.string().length(2, 'Pick a state'),
  phone: z.string().min(7).max(40),
});

export type OrganizationFormValues = z.infer<typeof organizationSchema>;
