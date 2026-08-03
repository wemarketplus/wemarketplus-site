import { z } from 'zod';
import { APPLICATION_STATUS } from '../constants/applicationsConstants';

// Create/edit application form — mirrors CreateApplicationDto / UpdateApplicationDto
// (wemarketplus-backend/src/applications/dto). On CREATE, companyId is
// required UUIDs; references cannot be reassigned on update. awardAmountApproved
// and decisionDate are update-only fields.
const statusValues = Object.values(APPLICATION_STATUS) as [string, ...string[]];

const optionalNonNegativeNumber = z
  .number()
  .min(0, 'Must be zero or more')
  .optional()
  .or(z.nan().transform(() => undefined));

export const applicationSchema = z.object({
  companyId: z.string().uuid('Company id must be a valid UUID'),
  fundingOpportunityId: z.string().uuid('Funding id must be a valid UUID').optional().or(z.literal('')),
  status: z.enum(statusValues).optional().or(z.literal('')),
  awardAmountRequested: optionalNonNegativeNumber,
  awardAmountApproved: optionalNonNegativeNumber,
  submissionDate: z.string().optional(),
  decisionDate: z.string().optional(),
  notes: z.string().optional(),
});

export type ApplicationFormValues = z.infer<typeof applicationSchema>;
